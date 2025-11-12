import {
  jwtVerify,
  EmbeddedJWK,
  base64url,
  calculateJwkThumbprint,
  type JWTPayload,
  type JWK,
  type JWTHeaderParameters,
} from 'jose';

import { createHash } from 'crypto';
import {
  InvalidRequestError,
  InvalidProofError,
  InvalidTokenError,
} from '@internal/oauth2-bearer-utils';

export interface ConfirmationClaims {
  jkt: string;
}
interface DPoPJWTPayload extends JWTPayload {
  cnf?: ConfirmationClaims;
}

export type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  dpop?: string;
};

export type DPoPVerifierOptions = {
  jwt: string;
  accessTokenClaims: DPoPJWTPayload;
  url: string;
  headers: HeadersLike;
  method: string;
  iatOffset: number;
  iatLeeway: number;
  supportedAlgorithms: string[];
};

const UNRESERVED = /[A-Za-z0-9\-._~]/;

function isJsonObject(input: unknown): boolean {
  return (
    typeof input === 'object' &&
    input !== null &&
    !Array.isArray(input) &&
    !(input instanceof Map) &&
    !(input instanceof Set)
  );
}

function normalizePercentEncodings(s: string): string {
  // Replace each %xx byte:
  // - If it decodes to an unreserved ASCII char, decode it to that char.
  // - Otherwise keep it encoded, but normalize hex to uppercase.
  return s.replace(/%[0-9a-fA-F]{2}/g, (m) => {
    const byte = parseInt(m.slice(1), 16);
    const ch = String.fromCharCode(byte);
    return UNRESERVED.test(ch) ? ch : `%${m.slice(1).toUpperCase()}`;
  });
}

/**
 * Normalize a URL for DPoP `htu` comparison.
 *
 * Behavior:
 * - Parses with WHATWG `URL`; rejects invalid input.
 * - Host must be a valid hostname with optional `:port`; no schemes, slashes, queries, or fragments allowed.
 * - For `source === 'request'`: path must start with `/` and not look like a protocol.
 * - Removes query and fragment.
 * - Normalizes percent-encodings in the path.
 * - Returns `origin + pathname` for reliable comparison.
 *
 * @param input - The URL to normalize (either the inbound request URL or the `htu` claim).
 * @param source - Indicates whether `input` is from the HTTP request (`'request'`) or the DPoP proof (`'proof'`).
 * @returns The normalized URL string in the form `origin + pathname` (no query or fragment).
 * @throws {InvalidRequestError} When `source === 'request'` and parsing/validation fails.
 * @throws {InvalidProofError}   When `source === 'proof'` and parsing/validation fails.
 */
function normalizeUrl(input: string, source: 'request' | 'proof'): string {
  const HOST_RE = /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;
  const PROTOCOL_IN_PATH_RE = /^\/[a-z][a-z0-9+.-]*:\/\//i;

  try {
    const url = new URL(input);
    // Host validation (extra safety if Host header is abused)
    const host = url.host;

    if (
      typeof host !== 'string' ||
      host.length === 0 ||
      host.includes('://') ||
      host.includes('/') ||
      host.includes('?') ||
      host.includes('#') ||
      !HOST_RE.test(host)
    ) {
      if (source === 'request') {
        throw new InvalidRequestError(
          'Invalid request URL: Host contains illegal characters or format'
        );
      } else {
        throw new InvalidProofError(
          'Invalid htu claim URL: Host contains illegal characters or format'
        );
      }
    }

    // Path checks for request URLs only
    if (source === 'request') {
      const path = url.pathname;

      // Reject protocol-relative paths (e.g., "//host/...")
      if (path.startsWith('//')) {
        throw new InvalidRequestError(
          `Invalid request URL: Path must not start with "//"`
        );
      }

      // Reject protocol-looking substrings inside the path (e.g., "/https://…")
      if (PROTOCOL_IN_PATH_RE.test(path)) {
        throw new InvalidRequestError(
          `Invalid request URL: Path must not contain an absolute URL`
        );
      }
    }

    // Canonicalize for htu comparison
    url.search = '';
    url.hash = '';
    url.pathname = normalizePercentEncodings(url.pathname);

    return url.origin + url.pathname;
  } catch (err) {
    // Preserve descriptive errors thrown above; only map unexpected ones.
    if (source === 'request') {
      if (err instanceof InvalidRequestError) throw err;
      throw new InvalidRequestError('Invalid request URL');
    } else {
      if (err instanceof InvalidProofError) throw err;
      throw new InvalidProofError('Invalid htu claim URL');
    }
  }
}

/*
 * Asserts that the request is a valid DPoP request.
 * Throws InvalidRequestError if the request is not a valid DPoP request.
 *
 * @method assertDPoPRequest
 * @param headers - The request headers containing the DPoP proof
 * @param accessTokenClaims - The JWT Access Token claims (optional)
 * @throws {InvalidRequestError} If the request is not a valid DPoP request
 */
function assertDPoPRequest(
  headers: HeadersLike,
  accessTokenClaims?: DPoPJWTPayload
): void {
  // Check if the request has an Authorization HTTP Header
  if (
    headers.authorization === undefined ||
    headers.authorization === null ||
    !('authorization' in headers)
  ) {
    throw new InvalidRequestError('', false);
  }

  if (typeof headers.authorization !== 'string') {
    throw new InvalidRequestError('', false);
  }

  // Check for correct Authorization scheme
  if (!headers.authorization.toLowerCase().startsWith('dpop ')) {
    throw new InvalidRequestError('', false);
  }

  // Check for DPoP HTTP Header
  if (!('dpop' in headers)) {
    throw new InvalidRequestError('', false);
  }

  // Ensure DPoP HTTP Header is a string
  if (typeof headers.dpop !== 'string') {
    throw new InvalidRequestError('', false);
  }

  // Ensure DPoP HTTP Header is not empty
  if (!headers.dpop.length) {
    throw new InvalidRequestError('', false);
  }

  // Ensure a single DPoP proof
  if (headers.dpop.includes(',')) {
    throw new InvalidRequestError('', false);
  }

  // If accessTokenClaims is provided, validate the confirmation "cnf" claims
  if (accessTokenClaims) {
    const { cnf } = accessTokenClaims;

    if (!cnf) {
      throw new InvalidTokenError(
        'JWT Access Token has no jkt confirmation claim'
      );
    }

    if (!isJsonObject(cnf)) {
      throw new InvalidTokenError('Invalid "cnf" confirmation claim structure');
    }

    if (Object.keys(cnf).length > 1) {
      throw new InvalidTokenError(
        'Multiple confirmation claims are not supported'
      );
    }

    if (!('jkt' in cnf)) {
      throw new InvalidTokenError(
        'JWT Access Token has no jkt confirmation claim'
      );
    }

    if (typeof cnf.jkt !== 'string') {
      throw new InvalidTokenError('Malformed "jkt" confirmation claim');
    }

    if (!cnf.jkt.length) {
      throw new InvalidTokenError('Invalid "jkt" confirmation claim');
    }
  }
}

/*
 * Verifies the DPoP proof claims.
 * Throws InvalidProofError if verification fails.
 *
 * @method verifyProof
 * @param headers - The request headers containing the DPoP proof
 * @returns An object containing the verified proof claims and header
 */
async function verifyProof(
  jws: string | undefined,
  supportedAlgorithms: string[]
): Promise<{ proofClaims: JWTPayload; proofHeader: JWTHeaderParameters }> {
  try {
    const verified = await jwtVerify(jws as string, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: supportedAlgorithms,
    });

    // Verify the DPoP proof JWT
    const proofClaims: JWTPayload = verified.payload;
    const proofHeader: JWTHeaderParameters = verified.protectedHeader;

    return { proofClaims, proofHeader };
  } catch (err) {
    let message = 'Failed to verify DPoP proof';
    if (err instanceof Error) {
      message = err.message;
    }

    // Fallback for unexpected errors
    throw new InvalidProofError(message);
  }
}

async function verifyDPoP(options: DPoPVerifierOptions): Promise<void> {
  const {
    jwt,
    accessTokenClaims,
    url,
    headers,
    method,
    iatOffset,
    iatLeeway,
    supportedAlgorithms,
  } = options;
  // Ensure the request is a DPoP request
  assertDPoPRequest(headers, accessTokenClaims);

  // Ensure a valid JWT is provided
  if (!jwt || typeof jwt !== 'string') {
    throw new InvalidTokenError('Missing access token for DPoP verification');
  }

  // Verify the DPoP proof JWT
  const { proofClaims, proofHeader } = await verifyProof(
    headers.dpop,
    supportedAlgorithms
  );

  const { htm, htu, iat, jti, ath } = proofClaims;

  // Ensure iat exists and is a number
  if (!iat) {
    throw new InvalidProofError('Missing "iat" claim in DPoP proof');
  }

  // Ensure iat is a number
  /* istanbul ignore next: "jwtVerify" is already validating the type of "iat" claim.  */
  if (typeof iat !== 'number') {
    throw new InvalidProofError('"iat" claim must be a number');
  }

  const now = Math.floor(Date.now() / 1000);
  const min = now - iatOffset;
  const max = now + iatLeeway;

  // Accepts proofs issued within the last `iatOffset` seconds, and up to `iatLeeway` in future
  if (iat < min || iat > max) {
    throw new InvalidProofError(
      'DPoP proof "iat" is outside the acceptable range'
    );
  }

  // Ensure htm exists
  if (!htm) {
    throw new InvalidProofError('Missing "htm" in DPoP proof');
  }

  // Ensure htm is a string
  if (typeof htm !== 'string') {
    throw new InvalidProofError('Invalid "htm" claim');
  }

  // Validate htm against the request method
  if (htm.toUpperCase() !== method.toUpperCase()) {
    throw new InvalidProofError('DPoP Proof htm mismatch');
  }

  // Ensure htu exists
  if (!htu) {
    throw new InvalidProofError('Missing "htu" in DPoP proof');
  }

  // Ensure htu is a string
  if (typeof htu !== 'string') {
    throw new InvalidProofError('Invalid "htu" claim');
  }

  // Normalize the htu claim to a canonical form and compare it with the request URL
  if (url !== normalizeUrl(htu, 'proof')) {
    throw new InvalidProofError('DPoP Proof htu mismatch');
  }

  // Validate jti
  if (!jti) {
    throw new InvalidProofError('Missing "jti" in DPoP proof');
  }

  // Validate ath hash of access token
  if (!ath) {
    throw new InvalidProofError('Missing "ath" claim in DPoP proof');
  }

  // Ensure ath is a string
  if (typeof ath !== 'string') {
    throw new InvalidProofError('Invalid "ath" claim');
  }

  // Calculate the hash of the JWT access token and encode it.
  const hash = createHash('sha256').update(jwt).digest();
  const encodedHash = base64url.encode(hash);
  if (ath !== encodedHash) {
    throw new InvalidProofError('DPoP Proof "ath" mismatch');
  }

  // Validate jkt == jwk thumbprint
  const expected = await calculateJwkThumbprint(proofHeader.jwk as JWK);
  if (accessTokenClaims?.cnf?.jkt !== expected) {
    // @see https://datatracker.ietf.org/doc/html/rfc9449#figure-16
    throw new InvalidTokenError('JWT Access Token confirmation mismatch');
  }
}

export {
  isJsonObject,
  normalizeUrl,
  assertDPoPRequest,
  verifyProof,
  verifyDPoP,
};
export type { DPoPJWTPayload };
