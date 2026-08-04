import { base64url, type JWTPayload } from 'jose';
import { createHash } from 'crypto';
import { InvalidRequestError, InvalidTokenError } from 'oauth2-bearer';
import { isJsonObject } from './dpop-verifier';

/**
 * The `x5t#S256` confirmation claim (RFC 8705 §3.1): the base64url-encoded
 * SHA-256 hash of the DER encoding of the client certificate the token is
 * bound to.
 */
export interface MtlsConfirmationClaims {
  'x5t#S256': string;
}

interface MtlsJWTPayload extends JWTPayload {
  cnf?: MtlsConfirmationClaims;
}

/**
 * A client certificate presented on the TLS connection, obtained by the
 * caller-supplied resolver. Either the PEM text (as produced by most
 * TLS-terminating proxies, typically URL-decoded first) or the raw DER bytes
 * (e.g. `req.socket.getPeerCertificate().raw`).
 */
export type ClientCertificate = string | Buffer | Uint8Array;

export type MtlsVerifierOptions = {
  accessTokenClaims: JWTPayload;
  clientCertificate: ClientCertificate | undefined;
};

const PEM_RE =
  /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/;

/**
 * Converts a client certificate to its DER-encoded bytes.
 *
 * Accepts a PEM string (single certificate), or a Buffer/Uint8Array that is
 * assumed to already be the DER encoding.
 *
 * @throws {InvalidRequestError} If a PEM string cannot be parsed.
 */
function toDer(cert: ClientCertificate): Buffer {
  if (typeof cert === 'string') {
    const match = cert.match(PEM_RE);
    if (!match) {
      throw new InvalidRequestError(
        'Client certificate is not valid PEM',
        false
      );
    }
    // Strip whitespace from the base64 body before decoding.
    return Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
  }

  return Buffer.isBuffer(cert) ? cert : Buffer.from(cert);
}

/**
 * Computes the RFC 8705 certificate thumbprint: base64url(SHA-256(DER)).
 *
 * @throws {InvalidRequestError} If the certificate cannot be decoded.
 */
function calculateCertificateThumbprint(cert: ClientCertificate): string {
  const der = toDer(cert);

  if (der.length === 0) {
    throw new InvalidRequestError('Client certificate is empty', false);
  }

  const hash = createHash('sha256').update(der).digest();
  return base64url.encode(hash);
}

/**
 * Validates the structure of the `cnf` confirmation claim for a
 * certificate-bound access token and returns the `x5t#S256` thumbprint.
 *
 * Mirrors the DPoP `cnf` guards: the claim must be a single-key JSON object
 * carrying a non-empty string `x5t#S256`.
 *
 * @throws {InvalidTokenError} If the confirmation claim is missing or malformed.
 */
function assertCertificateConfirmation(accessTokenClaims: JWTPayload): string {
  const cnf = accessTokenClaims.cnf;

  if (!cnf) {
    throw new InvalidTokenError(
      'JWT Access Token has no x5t#S256 confirmation claim'
    );
  }

  if (!isJsonObject(cnf)) {
    throw new InvalidTokenError('Invalid "cnf" confirmation claim structure');
  }

  const confirmation = cnf as Record<string, unknown>;

  if (Object.keys(confirmation).length > 1) {
    throw new InvalidTokenError(
      'Multiple confirmation claims are not supported'
    );
  }

  if (!('x5t#S256' in confirmation)) {
    throw new InvalidTokenError(
      'JWT Access Token has no x5t#S256 confirmation claim'
    );
  }

  const thumbprint = confirmation['x5t#S256'];

  if (typeof thumbprint !== 'string') {
    throw new InvalidTokenError('Malformed "x5t#S256" confirmation claim');
  }

  if (!thumbprint.length) {
    throw new InvalidTokenError('Invalid "x5t#S256" confirmation claim');
  }

  return thumbprint;
}

/**
 * Verifies that a certificate-bound access token (RFC 8705) matches the client
 * certificate presented on the TLS connection.
 *
 * The token's `cnf.x5t#S256` claim is compared against the base64url-encoded
 * SHA-256 thumbprint of the presented certificate. The certificate is obtained
 * by the caller (typically from a TLS-terminating proxy header) and passed in;
 * this verifier is transport-agnostic.
 *
 * @throws {InvalidRequestError} If the token is cert-bound but no certificate
 *   was presented, or the certificate cannot be decoded.
 * @throws {InvalidTokenError} If the confirmation claim is malformed or the
 *   thumbprint does not match the presented certificate.
 */
async function verifyMtls(options: MtlsVerifierOptions): Promise<void> {
  const { accessTokenClaims, clientCertificate } = options;

  const expected = assertCertificateConfirmation(accessTokenClaims);

  if (clientCertificate === undefined || clientCertificate === null) {
    throw new InvalidRequestError(
      'A client certificate is required for this certificate-bound access token'
    );
  }

  const actual = calculateCertificateThumbprint(clientCertificate);

  if (actual !== expected) {
    // @see https://www.rfc-editor.org/rfc/rfc8705#section-3.2
    throw new InvalidTokenError('JWT Access Token confirmation mismatch');
  }
}

export {
  calculateCertificateThumbprint,
  assertCertificateConfirmation,
  verifyMtls,
};
export type { MtlsJWTPayload };
