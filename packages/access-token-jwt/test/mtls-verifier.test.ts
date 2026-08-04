import {
  calculateCertificateThumbprint,
  assertCertificateConfirmation,
  verifyMtls,
  type MtlsJWTPayload,
} from '../src/mtls-verifier';

import { InvalidRequestError, InvalidTokenError } from 'oauth2-bearer';

import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import { writeFileSync, rmSync, readFileSync, mkdirSync } from 'fs';

// A real self-signed certificate generated once for the suite, plus a second,
// unrelated certificate to exercise thumbprint mismatches.
let certPem: string;
let certDer: Buffer;
let thumbprint: string;
let otherCertPem: string;
let otherThumbprint: string;

function generateCert(dir: string, cn: string): { pem: string } {
  const key = join(dir, `${cn}.key`);
  const crt = join(dir, `${cn}.crt`);
  execFileSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-keyout',
    key,
    '-out',
    crt,
    '-days',
    '1',
    '-nodes',
    '-subj',
    `/CN=${cn}`,
  ]);
  return { pem: readFileSync(crt, 'utf8') };
}

function base64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

beforeAll(() => {
  const dir = join(tmpdir(), `mtls-test-${process.pid}`);
  mkdirSync(dir, { recursive: true });
  try {
    certPem = generateCert(dir, 'client').pem;
    otherCertPem = generateCert(dir, 'other').pem;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const PEM_RE =
    /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/;
  certDer = Buffer.from(certPem.match(PEM_RE)![1].replace(/\s+/g, ''), 'base64');
  thumbprint = base64url(createHash('sha256').update(certDer).digest());

  const otherDer = Buffer.from(
    otherCertPem.match(PEM_RE)![1].replace(/\s+/g, ''),
    'base64'
  );
  otherThumbprint = base64url(createHash('sha256').update(otherDer).digest());
});

describe('calculateCertificateThumbprint', () => {
  it('computes base64url(SHA-256(DER)) from a PEM string', () => {
    expect(calculateCertificateThumbprint(certPem)).toBe(thumbprint);
  });

  it('computes the same thumbprint from DER bytes', () => {
    expect(calculateCertificateThumbprint(certDer)).toBe(thumbprint);
  });

  it('accepts a Uint8Array of DER bytes', () => {
    expect(calculateCertificateThumbprint(new Uint8Array(certDer))).toBe(
      thumbprint
    );
  });

  it('throws InvalidRequestError for a non-PEM string', () => {
    expect(() => calculateCertificateThumbprint('not a cert')).toThrow(
      InvalidRequestError
    );
  });

  it('throws InvalidRequestError for empty DER bytes', () => {
    expect(() => calculateCertificateThumbprint(Buffer.alloc(0))).toThrow(
      InvalidRequestError
    );
  });
});

describe('assertCertificateConfirmation', () => {
  it('returns the x5t#S256 thumbprint from a valid cnf claim', () => {
    const claims: MtlsJWTPayload = { cnf: { 'x5t#S256': thumbprint } };
    expect(assertCertificateConfirmation(claims)).toBe(thumbprint);
  });

  it('throws InvalidTokenError when cnf is missing', () => {
    expect(() => assertCertificateConfirmation({})).toThrow(InvalidTokenError);
  });

  it('throws InvalidTokenError when cnf is not an object', () => {
    expect(() =>
      assertCertificateConfirmation({ cnf: 'nope' } as unknown as MtlsJWTPayload)
    ).toThrow('Invalid "cnf" confirmation claim structure');
  });

  it('throws InvalidTokenError when cnf has more than one confirmation method', () => {
    const claims = {
      cnf: { 'x5t#S256': thumbprint, jkt: 'abc' },
    } as unknown as MtlsJWTPayload;
    expect(() => assertCertificateConfirmation(claims)).toThrow(
      'Multiple confirmation claims are not supported'
    );
  });

  it('throws InvalidTokenError when x5t#S256 is absent', () => {
    const claims = { cnf: { jkt: 'abc' } } as unknown as MtlsJWTPayload;
    expect(() => assertCertificateConfirmation(claims)).toThrow(
      'no x5t#S256 confirmation claim'
    );
  });

  it('throws InvalidTokenError when x5t#S256 is not a string', () => {
    const claims = {
      cnf: { 'x5t#S256': 123 },
    } as unknown as MtlsJWTPayload;
    expect(() => assertCertificateConfirmation(claims)).toThrow(
      'Malformed "x5t#S256" confirmation claim'
    );
  });

  it('throws InvalidTokenError when x5t#S256 is an empty string', () => {
    const claims: MtlsJWTPayload = { cnf: { 'x5t#S256': '' } };
    expect(() => assertCertificateConfirmation(claims)).toThrow(
      'Invalid "x5t#S256" confirmation claim'
    );
  });
});

describe('verifyMtls', () => {
  it('resolves when the presented certificate matches the binding', async () => {
    await expect(
      verifyMtls({
        accessTokenClaims: { cnf: { 'x5t#S256': thumbprint } },
        clientCertificate: certPem,
      })
    ).resolves.toBeUndefined();
  });

  it('accepts a DER Buffer as the presented certificate', async () => {
    await expect(
      verifyMtls({
        accessTokenClaims: { cnf: { 'x5t#S256': thumbprint } },
        clientCertificate: certDer,
      })
    ).resolves.toBeUndefined();
  });

  it('throws InvalidRequestError when no certificate is presented', async () => {
    await expect(
      verifyMtls({
        accessTokenClaims: { cnf: { 'x5t#S256': thumbprint } },
        clientCertificate: undefined,
      })
    ).rejects.toThrow(InvalidRequestError);
  });

  it('throws InvalidTokenError when the thumbprint does not match', async () => {
    await expect(
      verifyMtls({
        accessTokenClaims: { cnf: { 'x5t#S256': otherThumbprint } },
        clientCertificate: certPem,
      })
    ).rejects.toThrow('JWT Access Token confirmation mismatch');
  });

  it('throws InvalidTokenError when the token has no cnf claim', async () => {
    await expect(
      verifyMtls({
        accessTokenClaims: {},
        clientCertificate: certPem,
      })
    ).rejects.toThrow(InvalidTokenError);
  });
});
