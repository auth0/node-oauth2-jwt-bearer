import { Request } from 'express';
import {
  JWTPayload,
  jwtVerify,
  importJWK,
  JWK,
  base64url,
  calculateJwkThumbprint,
} from 'jose';
import { createHash } from 'crypto';
import { LRUCache } from 'lru-cache';
import { InvalidTokenError, InvalidRequestError } from 'oauth2-bearer';

const DEFAULT_IAT_OFFSET = 300; // 5 minutes
const DEFAULT_IAT_LEEWAY = 30; // 30 seconds

export type JsonObject = { [Key in string]?: JsonValue };
export type JsonArray = JsonValue[];
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export interface ConfirmationClaims {
  'x5t#S256'?: string;
  jkt?: string;
  [claim: string]: JsonValue | undefined;
}

export interface DPoPJWTPayload extends JWTPayload {
  cnf?: ConfirmationClaims;
}

interface DPoPOptions {
  enabled?: boolean;
  required?: boolean;
  iatOffset?: number;
  iatLeeway?: number;
}

class InvalidProofError extends InvalidRequestError {
  constructor(message: string) {
    super(message);
    this.name = 'Invalid DPoP Proof';
    this.code = 'invalid_dpop_proof';
    this.status = 400;
    this.statusCode = 400;
  }
}

const jtiCache = new LRUCache<string, true>({
  max: 5000,
  ttl: 0,
});

// function isJsonObject<T = JsonObject>(input: unknown): input is T {
//   return input !== null && typeof input === 'object' && !Array.isArray(input);
// }

// Calculate the time-to-live for the jti cache
function getTTL(iatOffset: number, iatLeeway: number) {
  return (iatOffset + iatLeeway) * 1000;
}

// Normalize the htu claim to a canonical form
function normalizeHtu(uri: string): string {
  const u = new URL(uri);
  u.hash = '';
  u.search = '';
  // TODO: Should we normalize protocols and ports ?
  if (
    (u.protocol === 'https:' && u.port === '443') ||
    (u.protocol === 'http:' && u.port === '80')
  ) {
    u.port = '';
  }
  u.hostname = u.hostname.toLowerCase();
  return u.toString();
}

/**
 * Validates a DPoP proof against the request and JWT claims.
 * @param request - The Express request object.
 * @param jwt - The JWT access token.
 * @param jwtClaims - The decoded JWT claims.
 * @param options - Optional DPoP validation options.
 * @throws {InvalidProofError} If the DPoP proof is invalid.
 * @throws {InvalidTokenError} If the DPoP proof is replayed or mismatched.
 */
export async function validateDPoP(
  request: Request,
  jwt: string,
  jwtClaims: DPoPJWTPayload,
  options?: DPoPOptions
): Promise<void> {
  const iatOffset = options?.iatOffset ?? DEFAULT_IAT_OFFSET;
  const iatLeeway = options?.iatLeeway ?? DEFAULT_IAT_LEEWAY;

  const headers = request.headers as Record<string, string | string[] | undefined>;
  const url = `${request.protocol}://${request.get('host')}${request.originalUrl}`;

  // Check for correct Authorization scheme
  if (
    typeof headers.authorization !== 'string' ||
    !headers.authorization.toLowerCase().startsWith('dpop ')
  ) {
    throw new InvalidProofError('Authorization header scheme is not DPoP');
  }

  // Check for DPoP HTTP Header
  if (!headers.dpop) throw new InvalidProofError('Missing DPoP HTTP Header');

  // Ensure a single DPoP proof
  if (Array.isArray(headers.dpop)) {
    throw new InvalidProofError('Multiple DPoP headers are not allowed');
  }

  // Confirm cnf.jkt exists before validating proof
  if (typeof jwtClaims.cnf?.jkt !== 'string') {
    throw new InvalidProofError('Missing "jkt" confirmation claim');
  }

  const { payload: proofClaims, protectedHeader: proofHeader } = await jwtVerify(
    headers.dpop as string,
    async (header) => {
      // Check for jwk and alg in header
      if (!header.jwk) throw new InvalidProofError('Missing "jwk" in DPoP header');
      if (!header.alg) throw new InvalidProofError('Missing "alg" in DPoP header');

      // Ensure jwk does not contain private key
      if ('d' in header.jwk) {
        throw new InvalidProofError('DPoP proof must not contain private key');
      }
      return await importJWK(header.jwk as JWK, header.alg);
    }
  );

  // Validate protected header
  if (typeof proofHeader.typ !== 'string' || proofHeader.typ.trim().toLowerCase() !== 'dpop+jwt') {
    throw new InvalidProofError('Invalid "typ" in DPoP header');
  }

  const { htm, htu, iat, jti, ath } = proofClaims;

  // Validate iat
  if (!iat) throw new InvalidProofError('Missing "iat" claim in DPoP proof');
  const now = Math.floor(Date.now() / 1000);
  if (iat < now - iatOffset || iat > now + iatLeeway) {
    throw new InvalidTokenError('DPoP proof "iat" is outside the acceptable range');
  }

  // Validate htm
  if (!htm) throw new InvalidProofError('Missing "htm" in DPoP proof');
  if (typeof htm !== 'string') throw new InvalidProofError('Invalid "htm" claim');
  if (htm !== request.method) {
    throw new InvalidTokenError('DPoP Proof htm mismatch');
  }

  // Validate htu
  if (!htu) throw new InvalidProofError('Missing "htu" in DPoP proof');
  if (typeof htu !== 'string') throw new InvalidProofError('Invalid "htu" claim');
  if (typeof htu !== 'string' || normalizeHtu(htu) !== normalizeHtu(url)) {
    throw new InvalidTokenError('DPoP Proof htu mismatch');
  }

  // Validate jti
  if (!jti) throw new InvalidProofError('Missing "jti" in DPoP proof');
  const jtiHash = createHash('sha256').update(jti).digest('base64');
  const ttl = getTTL(iatOffset, iatLeeway);

  // Check for jti replay
  if (jtiCache.has(jtiHash)) {
    throw new InvalidTokenError('DPoP "jti" replay detected');
  }
  jtiCache.set(jtiHash, true, { ttl });

  // Validate ath hash of access token
  if (!ath) throw new InvalidProofError('Missing "ath" claim in DPoP proof');
  if (typeof ath !== 'string') throw new InvalidProofError('Invalid "ath" claim');
  const hash = createHash('sha256').update(jwt).digest();
  const encodedHash = base64url.encode(hash);
  if (ath !== encodedHash) {
    throw new InvalidTokenError('DPoP Proof "ath" mismatch');
  }

  // Validate jkt == jwk thumbprint
  const expected = await calculateJwkThumbprint(proofHeader.jwk as JWK);
  if (jwtClaims?.cnf?.jkt !== expected) {
    throw new InvalidTokenError('JWT Access Token confirmation mismatch');
  }
}

/**
 * Checks if DPoP is required for the request based on the headers and JWT claims.
 * @param request - The request.
 * @param claims - The decoded JWT claims.
 * @param options - Optional DPoP options.
 * @returns {boolean} - True if DPoP is required, false otherwise.
 */
export function isDPoPRequired(
  request: Request,
  claims: DPoPJWTPayload,
  options?: DPoPOptions
): boolean {
  const scheme = request.header('authorization')?.split(' ')[0]?.toLowerCase();
  const dpopRequired = options?.required ?? false;
  const dpopEnabled = options?.enabled ?? true;
  const dpopHeader = request.header('dpop');

  return (
    dpopEnabled &&
    (dpopRequired ||
      scheme === 'dpop' ||
      claims.cnf?.jkt !== undefined ||
      dpopHeader !== undefined)
  );
}
