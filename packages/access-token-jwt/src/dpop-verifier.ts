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
} from 'oauth2-bearer';

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

// Normalize the htu claim to a canonical form, throwing if the URL is invalid
function normalizeUrl(htu: string, source: 'request' | 'proof'): string {
  try {
    const url = new URL(htu);
    url.search = '';
    url.hash = '';

    url.pathname = normalizePercentEncodings(url.pathname);

    return url.href;
  } catch {
    if (source === 'request') {
      throw new InvalidRequestError('Invalid request URL');
    }
    throw new InvalidProofError('Invalid htu claim URL');
  }
}

function assertDPoPRequest(
  headers: HeadersLike,
  accessTokenClaims?: DPoPJWTPayload
): void {
  // Check if the request has an Authorization HTTP Header
  if (headers.authorization === undefined || headers.authorization === null || !('authorization' in headers)) {
    throw new InvalidRequestError(
      'Operation indicated DPoP use but the request is missing an Authorization HTTP Header'
    );
  }

  if (typeof headers.authorization !== 'string') {
    throw new InvalidRequestError(
      "Operation indicated DPoP use but the request's Authorization HTTP Header is malformed"
    );
  }

  // Check for correct Authorization scheme
  if (
    !headers.authorization.toLowerCase().startsWith('dpop ')
  ) {
    throw new InvalidRequestError(
      "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"
    );
  }

  // Check for correct Authorization HTTP Header format
  const { length } = headers.authorization.split(' ');
  if (length !== 2) {
    throw new InvalidRequestError('Invalid Authorization HTTP Header format');
  }

  // Check for DPoP HTTP Header
  if (!headers.dpop)
    throw new InvalidRequestError(
      'Operation indicated DPoP use but the request has no DPoP HTTP Header'
    );

  // Ensure DPoP HTTP Header is a string
  if (typeof headers.dpop !== 'string') {
    throw new InvalidRequestError('DPoP HTTP Header must be a string');
  }

  // Ensure a single DPoP proof
  if (headers.dpop.includes(',')) {
    throw new InvalidRequestError('Multiple DPoP headers are not allowed');
  }

  // If accessTokenClaims is provided, validate the confirmation "cnf" claims
  if (accessTokenClaims) {
    const { cnf } = accessTokenClaims;

    if (!cnf) {
      throw new InvalidRequestError(
        'Operation indicated DPoP use but the JWT Access Token has no confirmation claim'
      );
    }

    if (typeof cnf !== 'object' || Array.isArray(cnf)) {
      throw new InvalidRequestError(
        'Invalid "cnf" confirmation claim structure'
      );
    }

    if (Object.keys(cnf).length > 1) {
      throw new InvalidRequestError(
        'Multiple confirmation claims are not supported'
      );
    }

    if (!('jkt' in cnf)) {
      throw new InvalidRequestError(
        'Operation indicated DPoP use but the JWT Access Token has no jkt confirmation claim'
      );
    }

    if (typeof cnf.jkt !== 'string') {
      throw new InvalidRequestError(
        'Malformed "jkt" confirmation claim'
      );
    }

    if (!cnf.jkt.length) {
      throw new InvalidRequestError('Invalid "jkt" confirmation claim');
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

export { normalizeUrl, assertDPoPRequest, verifyProof, verifyDPoP };
export type { DPoPJWTPayload };
