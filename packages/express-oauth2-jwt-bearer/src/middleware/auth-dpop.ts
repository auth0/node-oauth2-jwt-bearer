import {
  jwtVerify,
  importJWK,
  calculateJwkThumbprint,
  JWK,
  base64url
} from 'jose';
import { createRemoteJWKSet } from 'jose';
import { createHash } from 'crypto';
import { LRUCache } from 'lru-cache';

// --- Error classes based on RFC 6750 §3.1 ---
export class UnauthorizedError extends Error {
  status = 401;
  statusCode = 401;
  headers = { 'WWW-Authenticate': 'Bearer realm="api"' };

  constructor(message = 'Unauthorized') {
    super(message);
    this.name = this.constructor.name;
  }
}

export class InvalidRequestError extends UnauthorizedError {
  code = 'invalid_request';
  status = 400;
  statusCode = 400;

  constructor(message = 'Invalid Request') {
    super(message);
    this.headers = { 'WWW-Authenticate': getDpopHeader(this.code, message) };
  }
}

export class InvalidTokenError extends UnauthorizedError {
  code = 'invalid_token';
  status = 401;
  statusCode = 401;

  constructor(message = 'Invalid Token') {
    super(message);
    this.headers = { 'WWW-Authenticate': getDpopHeader(this.code, message) };
  }
}

// --- Helper to format DPoP-specific WWW-Authenticate challenges per RFC 9449 §7.2 ---
const getDpopHeader = (error: string, description: string, algs: string[] = ['ES256']) => {
  const desc = description.replace(/"/g, "'");
  return `DPoP error="${error}", error_description="${desc}", algs="${algs.join(' ')}"`;
};

// --- Replay protection for DPoP proofs via unique jti cache per RFC 9449 §4.3 ---
const jtiCache = new LRUCache<string, true>({
  max: 5000,
  ttl: 1000 * 60 * 5 // 5 minutes
});

type DPoPProofPayload = {
  htm?: string;
  htu?: string;
  iat?: number;
  jti?: string;
  ath?: string;
};

type AccessTokenPayload = {
  cnf?: { jkt?: string };
  [key: string]: any;
};

/**
 * DPoP proof validation logic per RFC 9449 §4.3
 */
async function validateDPoPProof({
  proofJwt,
  method,
  url,
  accessToken
}: {
  proofJwt: string;
  method: string;
  url: string;
  accessToken: string;
}) {
  const { payload, protectedHeader } = await jwtVerify(proofJwt, async (header) => {
    if (!header.jwk) throw new InvalidRequestError('Missing jwk in DPoP header');

    // RFC 9449 §4.3: jwk must not contain private key
    if ('d' in header.jwk) throw new InvalidRequestError('DPoP proof must not contain private key');

    return await importJWK(header.jwk as JWK, header.alg);
  });

  // RFC 9449 §4.3: typ must be dpop+jwt
  if (protectedHeader.typ !== 'dpop+jwt') throw new InvalidRequestError('Invalid typ in DPoP header');

  // RFC 9449 §4.3: alg must be asymmetric and acceptable (e.g., ES256)
  if (!['ES256'].includes(protectedHeader.alg)) throw new InvalidRequestError('Unsupported DPoP algorithm');

  const { htm, htu, iat, jti, ath } = payload as DPoPProofPayload;

  // RFC 9449 §4.3: htm must match HTTP method
  if (htm !== method) throw new InvalidRequestError('htm mismatch');

  // RFC 9449 §4.3: htu must match URI (normalized per RFC 3986 §6.2)
  const normalize = (uri: string) => {
    const u = new URL(uri);
    u.hash = ''; u.search = '';
    if ((u.protocol === 'https:' && u.port === '443') || (u.protocol === 'http:' && u.port === '80')) {
      u.port = '';
    }
    u.hostname = u.hostname.toLowerCase();
    return u.toString();
  };
  if (htu !== normalize(url)) throw new InvalidRequestError('htu mismatch');

  // RFC 9449 §4.3: iat must be recent (within ±5 minutes)
  if (!iat) throw new InvalidRequestError('Missing iat');
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - iat) > 300) throw new InvalidRequestError('DPoP proof too old');

  // RFC 9449 §4.3: jti must be unique
  if (!jti) throw new InvalidRequestError('Missing jti');
  if (jtiCache.has(jti)) throw new InvalidRequestError('DPoP jti replay');
  jtiCache.set(jti, true);

  // RFC 9449 §4.3: ath must match hash of access token
  if (!ath) throw new InvalidRequestError('Missing ath');
  const hash = createHash('sha256').update(accessToken).digest();
  const encodedHash = base64url.encode(hash);
  if (ath !== encodedHash) throw new InvalidRequestError('ath mismatch');

  // RFC 9449 §4.3: calculate thumbprint for cnf.jkt binding check
  if (!protectedHeader.jwk) throw new InvalidRequestError('Missing jwk in protected header');
  return await calculateJwkThumbprint(protectedHeader.jwk as JWK);
}

/**
 * Express middleware enforcing DPoP in required mode (RFC 9449 §7.2)
 */
export function authDPoP(options: {
  issuerBaseURL: string;
  audience: string;
}) {
  const { issuerBaseURL, audience } = options;
  const remoteJwks = createRemoteJWKSet(new URL(`${issuerBaseURL}/.well-known/jwks.json`));

  return async function dpopMiddleware(req: any, res: any, next: any) {
    try {
      const authz = req.headers.authorization;

      // RFC 6750 §3.1: if no Authorization header, do not include error code
      if (!authz) {
        res.status(401);
        res.setHeader('WWW-Authenticate', 'DPoP algs="ES256"');
        return res.send('Unauthorized');
      }

      // RFC 9449 §7.2: reject if multiple Authorization headers include Bearer + DPoP
      const authzHeaders = req.headers['authorization'];
      if (Array.isArray(authzHeaders)) {
        const schemes = authzHeaders.map(h => h.split(' ')[0].toLowerCase());
        if (schemes.includes('bearer') && schemes.includes('dpop')) {
          res.status(400);
          res.setHeader('WWW-Authenticate', [
            `Bearer error="invalid_request", error_description="Multiple methods used to include access token"`,
            getDpopHeader('invalid_request', 'Multiple methods used to include access token')
          ]);
          return res.send('Bad Request: Multiple authentication schemes used');
        }
      }

      const [scheme, token] = authz.split(' ');
      if (!/^dpop$/i.test(scheme)) {
        // RFC 9449 §7.2: protected resource must reject DPoP-bound tokens sent with Bearer
        throw new InvalidRequestError('Authorization scheme must be DPoP');
      }

      const { payload } = await jwtVerify(token, remoteJwks, {
        issuer: issuerBaseURL.endsWith('/') ? issuerBaseURL : `${issuerBaseURL}/`,
        audience
      });

      const proof = req.headers.dpop;
      if (!proof) throw new InvalidTokenError('Missing DPoP proof');

      const dpopThumbprint = await validateDPoPProof({
        proofJwt: proof as string,
        method: req.method,
        url: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
        accessToken: token
      });

      // RFC 9449 §4.3: ensure DPoP proof is bound to access token via cnf.jkt
      const typedPayload = payload as AccessTokenPayload;
      if (typedPayload.cnf?.jkt !== dpopThumbprint) {
        throw new InvalidTokenError('DPoP thumbprint does not match token cnf');
      }

      req.auth = { token, payload };
      next();
    } catch (err: any) {
      console.log(err);
      res.status(err.statusCode || 401);
      res.setHeader(
        'WWW-Authenticate',
        err.headers?.['WWW-Authenticate'] ?? getDpopHeader('invalid_token', err.message)
      );
      res.send(err.message);
    }
  };
}
