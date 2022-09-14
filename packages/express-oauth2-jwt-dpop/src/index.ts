import { createHash } from 'crypto';
import { IncomingHttpHeaders, OutgoingHttpHeaders } from 'http';
import { Handler, NextFunction, Request, Response } from 'express';
import {
  jwtVerify,
  EmbeddedJWK,
  base64url,
  calculateJwkThumbprint,
  JWK,
} from 'jose';
import {
  jwtVerifier,
  JwtVerifierOptions,
  VerifyJwtResult as AuthResult,
} from 'access-token-jwt';
import type { JWTPayload } from 'access-token-jwt';

declare global {
  namespace Express {
    interface Request {
      auth?: AuthResult;
    }
  }
}

export class UnauthorizedError extends Error {
  status = 401;
  statusCode = 401;
  headers: OutgoingHttpHeaders;

  constructor(algs: string[], message = 'Unauthorized') {
    super(message);
    this.name = this.constructor.name;
    this.headers = { 'WWW-Authenticate': `DPoP algs="${algs.join(' ')}"` };
  }
}

export class InvalidTokenError extends UnauthorizedError {
  code = 'invalid_token';
  status = 400;
  statusCode = 400;

  constructor(algs: string[], message = 'Invalid Token') {
    super(algs, message);
    this.headers = {
      'WWW-Authenticate': `DPoP error="${this.code}",
      error_description="${this.message}", algs="${algs.join(' ')}"`,
    };
  }
}

const TOKEN_RE = /^DPoP (.+)$/i;
const getTokens = (headers: IncomingHttpHeaders) => {
  const [, accessToken] = headers.authorization?.match(TOKEN_RE) || [];
  const proof = headers.dpop;
  if (!accessToken || !proof || Array.isArray(proof)) {
    throw new UnauthorizedError(['RS256']);
  }
  return { accessToken, proof };
};

const verifyProof = async (
  proof: string,
  accessToken: string,
  req: Request
) => {
  let thumbprint;
  const { payload } = await jwtVerify(
    proof,
    async (...args) => {
      const [{ jwk }] = args;
      thumbprint = await calculateJwkThumbprint(jwk as JWK);
      return EmbeddedJWK(...args);
    },
    {
      maxTokenAge: 60,
      clockTolerance: 60,
      algorithms: ['RS256'],
      typ: 'dpop+jwt',
    }
  );

  if (typeof payload.jti !== 'string' || !payload.jti) {
    throw new Error('must have a jti string property');
  }

  if (payload.htm !== req.method) {
    throw new Error('htm mismatch');
  }

  const url = new URL(
    req.originalUrl,
    `${req.protocol}://${req.get('Host')}`
  ).toString();
  if (payload.htu !== url) {
    throw new Error(`htu mismatch: expected ${payload.htu}, got ${url}`);
  }

  const ath = base64url.encode(
    createHash('sha256').update(accessToken).digest()
  );
  if (payload.ath !== ath) {
    throw new Error('ath mismatch');
  }

  return { thumbprint };
};

export const auth = (opts: JwtVerifierOptions = {}): Handler => {
  const verifyAccessToken = jwtVerifier(opts);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { accessToken, proof } = getTokens(req.headers);
      const { thumbprint } = await verifyProof(proof, accessToken, req);
      req.auth = await verifyAccessToken(accessToken, {
        cnf: (cnf?: any) => cnf?.jkt === thumbprint,
      });
      next();
    } catch (e) {
      next(e);
    }
  };
};

export { JwtVerifierOptions as AuthOptions, AuthResult, JWTPayload };
export {
  FunctionValidator,
  Validator,
  Validators,
  JWTHeader,
  JSONPrimitive,
} from 'access-token-jwt';
