import { Request } from 'express';
import {
  JWTPayload,
  jwtVerify,
  importJWK,
  JWK,
  base64url,
  calculateJwkThumbprint,
  JWTHeaderParameters
} from 'jose';
import { createHash } from 'crypto';
import { InvalidRequestError, UnauthorizedError } from 'oauth2-bearer';

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

// Normalize the htu claim to a canonical form, throwing if the URL is invalid
export function normalizeHtu(htu: string, source: 'request' | 'proof'): string {
  try {
    const url = new URL(htu);
    url.search = '';
    url.hash = '';
    return url.href;
  } catch {
    if (source === 'request') {
      throw new InvalidRequestError(`Invalid request URL`);
    } 
    throw new InvalidProofError(`Invalid htu claim URL`);
  }
}


/**
 * Validates a DPoP proof against the request and JWT claims.
 * @param request - The Express request object.
 * @param jwt - The JWT access token.
 * @param jwtClaims - The decoded JWT claims.
 * @param options - Optional DPoP validation options.
 * @throws {InvalidProofError} If the DPoP proof is invalid or fails validation.
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
  const url = `${request.protocol}://${request.host}${request.originalUrl ?? request.url}`;

  // Check for correct Authorization scheme
  if (
    typeof headers.authorization !== 'string' ||
    !headers.authorization.toLowerCase().startsWith('dpop ')
  ) {
    throw new InvalidRequestError('Operation indicated DPoP use but the request\'s Authorization HTTP Header scheme is not DPoP');
  }

  // Check for DPoP HTTP Header
  if (!headers.dpop) throw new InvalidProofError('Operation indicated DPoP use but the request has no DPoP HTTP Header');

  // Ensure DPoP HTTP Header is a string
  if (typeof headers.dpop !== 'string') {
    throw new InvalidProofError('DPoP HTTP Header must be a string');
  }

  // Ensure a single DPoP proof
  if (headers.dpop.includes(',')) {
    throw new InvalidProofError('Multiple DPoP headers are not allowed');
  }

  // Confirm cnf.jkt exists before validating proof
  if (typeof jwtClaims.cnf?.jkt !== 'string') {
    throw new InvalidProofError('Operation indicated DPoP use but the JWT Access Token has no jkt confirmation claim');
  }

  // Verify the DPoP proof JWT
  let proofClaims: JWTPayload;
  let proofHeader: JWTHeaderParameters;

  try {
    const verified = await jwtVerify(
      headers.dpop as string,
      async (header) => {
        // Validate presence of `jwk`
        if (!header.jwk) {
          throw new InvalidProofError('Missing "jwk" in DPoP header');
        }

        // Validate presence of `alg`
        if (!header.alg) {
          throw new InvalidProofError('Missing "alg" in DPoP header');
        }

        // Validate the algorithm `alg`
        if (typeof header.alg !== 'string' || header.alg.trim() !== 'ES256') {
          throw new InvalidProofError('Unsupported algorithm');
        }

        // Prevent private key exposure
        if ('d' in header.jwk) {
          throw new InvalidProofError('DPoP proof must not contain private key material');
        }

        return await importJWK(header.jwk as JWK, header.alg);
      },
      {
        typ: 'dpop+jwt', // optional but stricter
        algorithms: ['ES256'], // only allow ES256
      }
    );

    proofClaims = verified.payload;
    proofHeader = verified.protectedHeader;
  } catch (err) {
    if (err instanceof Error) {
      throw new InvalidProofError(err.message);
    }

    // Fallback for unexpected errors
    throw new InvalidProofError('Failed to verify DPoP proof');
  }

  // Validate protected header
  if (typeof proofHeader.typ !== 'string' || proofHeader.typ.trim().toLowerCase() !== 'dpop+jwt') {
    throw new InvalidProofError('Invalid "typ" in DPoP header');
  }

  const { htm, htu, iat, jti, ath } = proofClaims;

  // Validate iat
  if (!iat) throw new InvalidProofError('Missing "iat" claim in DPoP proof');
  const now = Math.floor(Date.now() / 1000);
  if (iat < now - iatOffset || iat > now + iatLeeway) {
    throw new InvalidProofError('DPoP proof "iat" is outside the acceptable range');
  }

  // Validate htm
  if (!htm) throw new InvalidProofError('Missing "htm" in DPoP proof');
  if (typeof htm !== 'string') throw new InvalidProofError('Invalid "htm" claim');
  if (htm !== request.method) {
    throw new InvalidProofError('DPoP Proof htm mismatch');
  }

  // Validate htu
  if (!htu) throw new InvalidProofError('Missing "htu" in DPoP proof');
  if (typeof htu !== 'string') throw new InvalidProofError('Invalid "htu" claim');

  // Normalize and compare htu with the request URL
  if (normalizeHtu(htu, 'proof') !== normalizeHtu(url, 'request')) {
    throw new InvalidProofError('DPoP Proof htu mismatch');
  }

  // Validate jti
  if (!jti) throw new InvalidProofError('Missing "jti" in DPoP proof');

  // Validate ath hash of access token
  if (!ath) throw new InvalidProofError('Missing "ath" claim in DPoP proof');
  if (typeof ath !== 'string') throw new InvalidProofError('Invalid "ath" claim');
  const hash = createHash('sha256').update(jwt).digest();
  const encodedHash = base64url.encode(hash);
  if (ath !== encodedHash) {
    throw new InvalidProofError('DPoP Proof "ath" mismatch');
  }

  // Validate jkt == jwk thumbprint
  const expected = await calculateJwkThumbprint(proofHeader.jwk as JWK);
  if (jwtClaims?.cnf?.jkt !== expected) {
    throw new InvalidProofError('JWT Access Token confirmation mismatch');
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

/**
 * Checks if the request has a valid Authorization scheme.
 * If DPoP is not enabled, it only allows Bearer tokens.
 * @param request - The Express request object.
 * @param options - Optional DPoP options.
 * @throws {InvalidRequestError} If the Authorization scheme is invalid.
 */
export function checkInvalidScheme(request: Request, options?: DPoPOptions): void {
  const dpopEnabled = options?.enabled ?? true;
  const dpopRequired = options?.required ?? false;

  const scheme = request.header('authorization')?.split(' ')[0]?.toLowerCase();

  if (dpopEnabled) {
    if (dpopRequired) {
      if (!scheme) {
        throw new InvalidRequestError('Expecting Authorization header with DPoP scheme');
      }

      if (scheme !== 'dpop') {
        throw new InvalidRequestError(`Invalid scheme. Expected 'DPoP', but got '${scheme}'.`);
      }
    } else {
      if (scheme && !['dpop', 'bearer'].includes(scheme.toLowerCase())) {
        // @see https://www.rfc-editor.org/rfc/rfc9449.html#section-7.2-6
        throw new UnauthorizedError();
      }
    }
  }

  if (!dpopEnabled && scheme) {
    if (scheme === 'dpop') {
      throw new InvalidRequestError('Invalid scheme. Can not use DPoP when it is not enabled.');
    }

    if (scheme !== 'bearer') {
      throw new InvalidRequestError(`Invalid scheme. Expected 'Bearer', but got '${scheme}'.`);
    }
  }
}
