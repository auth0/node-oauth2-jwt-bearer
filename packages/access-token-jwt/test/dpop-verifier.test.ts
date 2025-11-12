import {
  isJsonObject,
  normalizeUrl,
  assertDPoPRequest,
  verifyProof,
  verifyDPoP,
  type DPoPVerifierOptions,
} from '../src/dpop-verifier';

import {
  InvalidRequestError,
  InvalidProofError,
  InvalidTokenError,
} from '@internal/oauth2-bearer-utils';

import { HeadersLike } from '../src/token-verifier';

import {
  SignJWT,
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
  JWTPayload,
  type JWK,
} from 'jose';

import crypto from 'node:crypto';
import sinon from 'sinon';

let jwt: string;
let jwk: JWK;
let privateKey: import('jose').KeyLike;
let thumbprint: string;
let method: string;
let url: string;
let headers: Record<string, any>;

beforeEach(async () => {
  const { publicKey, privateKey: key } = await generateKeyPair('ES256');
  jwk = await exportJWK(publicKey);
  privateKey = key;
  thumbprint = await calculateJwkThumbprint(jwk);
  jwt = 'access.token.jwt';
  method = 'GET';
  url = 'https://api.example.com/resource';
  headers = {};
});

afterEach(() => sinon.restore());

function createATH(token = jwt) {
  return crypto.createHash('sha256').update(token).digest('base64url');
}

async function createProof(
  overrides: Record<string, any> = {},
  headerOverrides: Record<string, any> = {}
) {
  return new SignJWT({
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: createATH(),
    ...overrides,
  })
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk,
      ...headerOverrides,
    })
    .sign(privateKey);
}

function createOptions(
  overrides: Partial<DPoPVerifierOptions> = {}
): DPoPVerifierOptions {
  return {
    jwt,
    headers: {
      authorization: `DPoP ${jwt}`,
      dpop: headers.dpop,
      ...overrides.headers,
    },
    accessTokenClaims: { cnf: { jkt: thumbprint } },
    method,
    url,
    iatOffset: 300,
    iatLeeway: 60,
    supportedAlgorithms: ['ES256'],
    ...overrides,
  };
}

describe('isJsonObject', () => {
  it('returns true for plain objects', () => {
    expect(isJsonObject({})).toBe(true);
    expect(isJsonObject({ a: 1 })).toBe(true);
    expect(isJsonObject(Object.create(null))).toBe(true);
  });

  it('returns false for null', () => {
    expect(isJsonObject(null)).toBe(false);
  });

  it('returns true for objects created with Object.create(null)', () => {
    expect(isJsonObject(Object.create(null))).toBe(true);
  });

  it('isJsonObject | returns false for Map and Set', () => {
    expect(isJsonObject(new Map())).toBe(false);
    expect(isJsonObject(new Set())).toBe(false);
  });

  it('returns false for arrays', () => {
    expect(isJsonObject([])).toBe(false);
    expect(isJsonObject([1, 2, 3])).toBe(false);
  });

  it('returns false for primitive types', () => {
    expect(isJsonObject('string')).toBe(false);
    expect(isJsonObject(123)).toBe(false);
    expect(isJsonObject(true)).toBe(false);
    expect(isJsonObject(undefined)).toBe(false);
    expect(isJsonObject(Symbol('sym'))).toBe(false);
  });

  it('returns false for functions and arrow functions', () => {
    expect(
      isJsonObject(function () {
        return true;
      })
    ).toBe(false);
    expect(
      isJsonObject(() => {
        return true;
      })
    ).toBe(false);
  });

  it('returns true for class instances (object type)', () => {
    class MyClass {}
    const instance = new MyClass();
    expect(isJsonObject(instance)).toBe(true);
  });
});

describe('normalizeUrl', () => {
  it('removes query and fragment from URL (htu)', () => {
    const raw = 'https://api.example.com/resource?foo=bar#hash';
    const expected = 'https://api.example.com/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('preserves trailing slash if present', () => {
    const raw = 'https://api.example.com/resource/?abc=def';
    const expected = 'https://api.example.com/resource/';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('preserves non-default port in normalized URL', () => {
    const raw = 'https://api.example.com:8443/resource?foo=bar';
    const expected = 'https://api.example.com:8443/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('should not preserve username and password in URL (htu)', () => {
    const raw = 'https://user:pass@api.example.com/resource?foo=bar';
    const expected = 'https://api.example.com/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('normalizes localhost with port and query/hash', () => {
    const raw = 'http://localhost:3000/path?debug=true#frag';
    const expected = 'http://localhost:3000/path';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('supports IP addresses as hosts', () => {
    const raw = 'http://127.0.0.1:4000/test?foo=bar';
    const expected = 'http://127.0.0.1:4000/test';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('throws InvalidRequestError if request URL is invalid', () => {
    const malformed = 'ht!tp:/broken-url';
    expect(() => normalizeUrl(malformed, 'request')).toThrow(
      InvalidRequestError
    );
    expect(() => normalizeUrl(malformed, 'request')).toThrow(
      'Invalid request URL'
    );
  });

  it('throws InvalidProofError if proof htu is invalid', () => {
    const malformed = ':://foo.bar?x=1';
    expect(() => normalizeUrl(malformed, 'proof')).toThrow(InvalidProofError);
    expect(() => normalizeUrl(malformed, 'proof')).toThrow(
      'Invalid htu claim URL'
    );
  });

  it('should return the same URL when already normalized', () => {
    const input = 'https://api.example.com/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should normalize scheme and host casing', () => {
    const input = 'HTTPS://API.EXAMPLE.COM/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should remove default port (443)', () => {
    const input = 'https://api.example.com:443/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should normalize percent-encoding to uppercase', () => {
    const input = 'https://api.example.com/path%2fto%2fresource';
    const expected = 'https://api.example.com/path%2Fto%2Fresource';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('decodes unreserved percent-encodings (and keeps reserved encoded)', () => {
    const input = 'https://api.example.com/%7Euser/path%2Fwith%2Fslash';
    const expected = 'https://api.example.com/~user/path%2Fwith%2Fslash'; // ~ decoded, / kept encoded (uppercased)
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should resolve dot segments in path', () => {
    const input = 'https://api.example.com/path/../resource/./file.txt';
    const expected = 'https://api.example.com/resource/file.txt';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should strip query and fragment (request)', () => {
    const input = 'https://api.example.com/path?query=value#fragment';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should normalize full complex URL with auth, port, dot segments, and fragment', () => {
    const input =
      'HTTPS://USER:PASS@API.EXAMPLE.COM:443/path/../RESOURCE/./file.txt?query=value#fragment';
    const expected = 'https://api.example.com/RESOURCE/file.txt';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('host validation | rejects host with underscore (request)', () => {
    const input = 'https://bad_host.example/path';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(
      'Invalid request URL: Host contains illegal characters or format'
    );
  });

  it('host validation | rejects host with underscore (proof)', () => {
    const input = 'https://bad_host.example/path';
    expect(() => normalizeUrl(input, 'proof')).toThrow(InvalidProofError);
    expect(() => normalizeUrl(input, 'proof')).toThrow(
      'Invalid htu claim URL: Host contains illegal characters or format'
    );
  });

  it('host validation | accepts IPv6 literal host [::1] (request)', () => {
    const input = 'http://[::1]/path?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('http://[::1]/path');
  });

  it('host validation | accepts IPv6 literal host [::1] (proof)', () => {
    const input = 'http://[::1]/path?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe('http://[::1]/path');
  });

  it('host validation | rejects overlong port (6+ digits)', () => {
    const input = 'https://api.example.com:999999/path';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow('Invalid request URL');
  });

  it('host validation | accepts punycode hostnames', () => {
    const input = 'https://xn--bcher-kva.de/path';
    const expected = 'https://xn--bcher-kva.de/path';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  it('host validation | accepts trailing dot in hostname', () => {
    const input = 'https://example.com./x';
    const expected = 'https://example.com./x';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  it('host validation | accepts IPv6 literal with port (request)', () => {
    const input = 'http://[2001:db8::1]:8080/alpha?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe(
      'http://[2001:db8::1]:8080/alpha'
    );
  });

  it('host validation | accepts IPv6 literal with port (proof)', () => {
    const input = 'http://[2001:db8::1]:3000/path?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe('http://[2001:db8::1]:3000/path');
  });

  it('host validation | rejects malformed IPv6 literal (missing closing bracket)', () => {
    const input = 'http://[2001:db8::1/path';
    // WHATWG URL will throw a TypeError; we map to generic InvalidRequestError
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow('Invalid request URL');
  });

  it('path checks | rejects protocol-relative path (request)', () => {
    const input = 'https://api.example.com//evil.example.com/steal';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(
      'Invalid request URL: Path must not start with "//"'
    );
  });

  it('path checks | allows "//" sequence for proof', () => {
    const input = 'https://api.example.com//double/slash?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe(
      'https://api.example.com//double/slash'
    );
  });

  it('path checks | rejects protocol-looking substring right after "/" in path (request)', () => {
    const input = 'https://api.example.com/https://evil.example.com/steal';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(
      'Invalid request URL: Path must not contain an absolute URL'
    );
  });

  it('path checks | does not apply the path protocol check to proof', () => {
    const input =
      'https://api.example.com/https://evil.example.com/steal?x=1#y';
    const expected = 'https://api.example.com/https://evil.example.com/steal';
    expect(normalizeUrl(input, 'proof')).toBe(expected);
  });

  it('malformed URLs | rejects protocol-relative path derived from double-scheme (request)', () => {
    const input = 'https://https://resource.com/intendedPath?/targetPath';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(
      'Invalid request URL: Path must not start with "//"'
    );
  });

  it('malformed URLs and parser failures | throws generic InvalidProofError on URL parse failure (proof)', () => {
    const input = '::::://';
    expect(() => normalizeUrl(input, 'proof')).toThrow(InvalidProofError);
    expect(() => normalizeUrl(input, 'proof')).toThrow('Invalid htu claim URL');
  });

  it('origin + pathname output shape | strips credentials (userinfo) by returning origin + pathname (request)', () => {
    const raw = 'https://user:pass@api.example.com/secure?x=1#frag';
    const expected = 'https://api.example.com/secure';
    expect(normalizeUrl(raw, 'request')).toBe(expected);
  });

  it('origin + pathname output shape | keeps non-default port and lowercases scheme/host', () => {
    const raw = 'HTTPS://API.EXAMPLE.COM:8443/A/Path?Q=1#F';
    const expected = 'https://api.example.com:8443/A/Path';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  it('scheme normalization | strips default port 80 for http', () => {
    const input = 'http://api.example.com:80/path?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('http://api.example.com/path');
  });

  it('IDN host | Unicode hostname is normalized to punycode', () => {
    const input = 'https://bücher.de/weg';
    // WHATWG URL serializes to punycode
    expect(normalizeUrl(input, 'proof')).toBe('https://xn--bcher-kva.de/weg');
  });

  it('percent-encoding | non-ASCII bytes remain encoded with uppercase hex', () => {
    const input = 'https://api.example.com/price/%e2%82%ac';
    const expected = 'https://api.example.com/price/%E2%82%AC';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  it('path semantics | encoded dot-segments collapse after decode', () => {
    const input = 'https://api.example.com/a/%2e%2e/b';
    const expected = 'https://api.example.com/b';
    expect(normalizeUrl(input, 'proof')).toBe(expected);
  });

  it('IPv4-mapped IPv6 | canonicalizes embedded IPv4 to hex groups', () => {
    const input = 'http://[::ffff:192.0.2.128]:3000/x';
    expect(normalizeUrl(input, 'proof')).toBe(
      'http://[::ffff:c000:280]:3000/x'
    );
  });
});

describe('assertDPoPRequest', () => {
  const baseHeaders = (): HeadersLike => ({
    authorization: `DPoP ${jwt}`,
    dpop: 'header.payload.signature',
  });

  const validClaims = () => ({ cnf: { jkt: thumbprint } });
  const expectPass = (headers: HeadersLike, claims?: JWTPayload) => {
    expect(() => assertDPoPRequest(headers, claims)).not.toThrow();
  };

  const expectFail = (
    headers: HeadersLike,
    claims?: JWTPayload,
    msgIncludes?: string,
    errorClass?: any
  ) => {
    try {
      assertDPoPRequest(headers, claims);
      throw new Error('Expected assertDPoPRequest to throw');
    } catch (err: any) {
      expect(err).toBeInstanceOf(errorClass ?? InvalidRequestError);
      if (msgIncludes) {
        expect(String(err.message)).toContain(msgIncludes);
      }
    }
  };

  it('passes with valid headers and cnf.jkt', () => {
    expectPass(baseHeaders(), validClaims());
  });

  it('passes with valid headers when accessTokenClaims is not provided', () => {
    expectPass(baseHeaders());
  });

  it('accepts mixed-case DPoP scheme', () => {
    const headers = baseHeaders();
    headers.authorization = `dPoP ${jwt}`;
    expectPass(headers, validClaims());
  });

  it('passes when headers include unrelated extra properties', () => {
    const headers = { ...baseHeaders(), 'x-extra': 'ok' };
    expectPass(headers, validClaims());
  });

  it('fails when Authorization is missing', () => {
    const headers = baseHeaders();
    delete headers.authorization;
    expectFail(headers, validClaims(), '');
  });

  it('fails when Authorization is null', () => {
    const headers = baseHeaders();
    headers.authorization = null as any;
    expectFail(headers, validClaims(), '');
  });

  it('fails when Authorization is not a string', () => {
    const headers = baseHeaders();
    headers.authorization = 123 as any;
    expectFail(headers, validClaims(), '');
  });

  it('fails when Authorization scheme is not DPoP (Bearer)', () => {
    const headers = baseHeaders();
    headers.authorization = `Bearer ${jwt}`;
    expectFail(headers, validClaims(), '');
  });

  it('fails when DPoP header is missing', () => {
    const headers = baseHeaders();
    delete headers.dpop;
    expectFail(headers, validClaims(), '');
  });

  it('fails when DPoP header is null', () => {
    const headers = baseHeaders();
    headers.dpop = null as any;
    expectFail(headers, validClaims(), '');
  });

  it('fails when DPoP header is not a string', () => {
    const headers = baseHeaders();
    headers.dpop = { not: 'a string' } as any;
    expectFail(headers, validClaims(), '');
  });

  it('fails when DPoP header is an empty string', () => {
    const headers = baseHeaders();
    headers.dpop = '';
    expectFail(headers, validClaims(), '');
  });

  it('fails when multiple DPoP headers are provided (comma-separated)', () => {
    const headers = baseHeaders();
    headers.dpop = 'proof1,proof2';
    expectFail(headers, validClaims(), '');
  });

  it('fails when accessTokenClaims.cnf is missing', () => {
    expectFail(
      baseHeaders(),
      {},
      'JWT Access Token has no jkt confirmation claim',
      InvalidTokenError
    );
  });

  it('fails when cnf is not an object (string)', () => {
    expectFail(
      baseHeaders(),
      { cnf: 'bad' },
      'Invalid "cnf" confirmation claim structure',
      InvalidTokenError
    );
  });

  it('fails when cnf is an array', () => {
    expectFail(
      baseHeaders(),
      { cnf: [] },
      'Invalid "cnf" confirmation claim structure',
      InvalidTokenError
    );
  });

  it('fails when cnf contains multiple keys', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: 'thumb', extra: 'x' } },
      'Multiple confirmation claims are not supported',
      InvalidTokenError
    );
  });

  it('fails when cnf.jkt is missing (undefined)', () => {
    expectFail(
      baseHeaders(),
      { cnf: {} },
      'JWT Access Token has no jkt confirmation claim',
      InvalidTokenError
    );
  });

  it('fails when cnf.jkt is not a string', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: 123 } },
      'Malformed "jkt" confirmation claim',
      InvalidTokenError
    );
  });

  it('fails when cnf.jkt is an empty string', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: '' } },
      'Invalid "jkt" confirmation claim',
      InvalidTokenError
    );
  });

  it('passes when cnf.jkt is a non-empty string', () => {
    expectPass(baseHeaders(), { cnf: { jkt: 'abc' } });
  });

  it('fails early with a clear message when headers is an empty object', () => {
    expectFail({}, validClaims(), '');
  });
});

describe('verifyProof', () => {
  it('verifies a valid DPoP proof and returns claims and protected header', async () => {
    const proof = await createProof(); // ES256 + typ dpop+jwt + jwk + standard claims

    const { proofClaims, proofHeader } = await verifyProof(proof, ['ES256']);

    expect(proofClaims).toMatchObject({
      htm: method,
      htu: url,
      iat: expect.any(Number),
      jti: expect.any(String),
      ath: expect.any(String),
    });

    expect(proofHeader).toMatchObject({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: expect.any(Object),
    });
  });

  it('throws InvalidProofError for undefined JWS', async () => {
    await expect(verifyProof(undefined as any, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(undefined as any, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|Compact JWS must be a string or Uint8Array/
    );
  });

  it('throws InvalidProofError for malformed JWS (not 3 parts)', async () => {
    await expect(verifyProof('abc.def', ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof('abc.def', ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|Invalid Compact JWS/
    );
  });

  it('throws InvalidProofError when typ header is incorrect', async () => {
    const proof = await createProof({}, { typ: 'wrong' });
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|unexpected "typ" JWT header value/
    );
  });

  it('throws InvalidProofError when typ header is missing', async () => {
    const proof = await createProof({}, { typ: undefined });
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|unexpected "typ" JWT header value/
    );
  });

  it('throws InvalidProofError when algorithm in proof is not in supportedAlgorithms', async () => {
    // Create RS256 proof and only allow ES256
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const rsJwk = await exportJWK(publicKey);

    const proof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: createATH(),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'RS256', jwk: rsJwk })
      .sign(privateKey);

    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|"alg" \(Algorithm\) Header Parameter not allowed/
    );
  });

  it('verifies when algorithm is supported (whitelist works)', async () => {
    const proof = await createProof(); // ES256
    await expect(verifyProof(proof, ['ES256'])).resolves.toBeTruthy();
  });

  it('throws InvalidProofError when signature is invalid (tampered)', async () => {
    const proof = await createProof();
    const tampered = proof + 'tampered';
    await expect(verifyProof(tampered, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(tampered, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|signature verification failed/
    );
  });

  it('throws InvalidProofError when jwk is missing from protected header', async () => {
    const proof = await createProof({}, { jwk: undefined });
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|"jwk" \(JSON Web Key\) Header Parameter must be a JSON object/
    );
  });

  it('throws InvalidProofError when jwk header is malformed (not an object)', async () => {
    const proof = await createProof({}, { jwk: 'not-an-object' as any });
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      InvalidProofError
    );
    await expect(verifyProof(proof, ['ES256'])).rejects.toThrow(
      /Failed to verify DPoP proof|"jwk" \(JSON Web Key\) Header Parameter must be a JSON object/
    );
  });
});

describe('verifyDPoP', () => {
  it('passes for a valid proof', async () => {
    headers.dpop = await createProof();
    await expect(verifyDPoP(createOptions())).resolves.toBeUndefined();
  });

  it('fails when headers are invalid (delegates to assertDPoPRequest)', async () => {
    // No authorization or dpop -> assertDPoPRequest should throw
    const opts = createOptions({ headers: {} as any });
    const fn = verifyDPoP(opts);
    await expect(fn).rejects.toThrow(InvalidRequestError);
    await expect(fn).rejects.toThrow('');
  });

  it('fails when access token (jwt) is missing', async () => {
    headers.dpop = await createProof();
    const opts = createOptions();
    delete (opts as any).jwt;
    const fn = verifyDPoP(opts);
    await expect(fn).rejects.toThrow(InvalidTokenError);
    await expect(fn).rejects.toThrow(
      'Missing access token for DPoP verification'
    );
  });

  it('fails when access token (jwt) is not a string', async () => {
    headers.dpop = await createProof();
    const opts = createOptions();
    opts.jwt = 123 as any; // Not a string
    const fn = verifyDPoP(opts);
    await expect(fn).rejects.toThrow(InvalidTokenError);
    await expect(fn).rejects.toThrow(
      'Missing access token for DPoP verification'
    );
  });

  it('fails when proof is signed with an unsupported algorithm', async () => {
    // Create RS256 proof but only allow ES256 to make verifyProof fail
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const rsJwk = await exportJWK(publicKey);
    const rsProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: createATH(),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'RS256', jwk: rsJwk })
      .sign(privateKey);

    headers.dpop = rsProof;
    const fn = verifyDPoP(createOptions({ supportedAlgorithms: ['ES256'] }));
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow(
      /Failed to verify DPoP proof|"alg" \(Algorithm\) Header Parameter not allowed/
    );
  });

  it('fails when iat is missing', async () => {
    headers.dpop = await createProof({ iat: undefined });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Missing "iat" claim in DPoP proof');
  });

  it('fails when iat is not a number', async () => {
    headers.dpop = await createProof({ iat: 'bad' as any });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('"iat" claim must be a number');
  });

  it('fails when iat is outside acceptable range (too old)', async () => {
    headers.dpop = await createProof({
      iat: Math.floor(Date.now() / 1000) - 1000,
    });

    const fn = verifyDPoP(createOptions({ iatOffset: 300, iatLeeway: 60 }));
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow(
      'DPoP proof "iat" is outside the acceptable range'
    );
  });

  it('fails when iat is outside acceptable range (in future)', async () => {
    headers.dpop = await createProof({
      iat: Math.floor(Date.now() / 1000) + 1000,
    });
    const fn = verifyDPoP(createOptions({ iatOffset: 300, iatLeeway: 60 }));
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow(
      'DPoP proof "iat" is outside the acceptable range'
    );
  });

  it('fails when htm is missing', async () => {
    headers.dpop = await createProof({ htm: undefined });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Missing "htm" in DPoP proof');
  });

  it('fails when htm is not a string', async () => {
    headers.dpop = await createProof({ htm: 123 as any });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Invalid "htm" claim');
  });

  it('fails when htm does not match request method', async () => {
    headers.dpop = await createProof({ htm: 'POST' });
    const fn = verifyDPoP(createOptions({ method: 'GET' }));
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('DPoP Proof htm mismatch');
  });

  it('fails when htu is missing', async () => {
    headers.dpop = await createProof({ htu: undefined });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Missing "htu" in DPoP proof');
  });

  it('fails when htu is not a string', async () => {
    headers.dpop = await createProof({ htu: 123 as any });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Invalid "htu" claim');
  });

  it('fails when normalized htu does not match request URL', async () => {
    headers.dpop = await createProof({ htu: 'https://api.example.com/other' });
    const fn = verifyDPoP(
      createOptions({ url: 'https://api.example.com/resource' })
    );
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('DPoP Proof htu mismatch');
  });

  it('fails when jti is missing', async () => {
    headers.dpop = await createProof({ jti: undefined });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Missing "jti" in DPoP proof');
  });

  it('fails when ath is missing', async () => {
    headers.dpop = await createProof({ ath: undefined });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Missing "ath" claim in DPoP proof');
  });

  it('fails when ath is not a string', async () => {
    headers.dpop = await createProof({ ath: 123 as any });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('Invalid "ath" claim');
  });

  it('fails when ath hash does not match access token', async () => {
    headers.dpop = await createProof({ ath: 'tampered' });
    const fn = verifyDPoP(createOptions());
    await expect(fn).rejects.toThrow(InvalidProofError);
    await expect(fn).rejects.toThrow('DPoP Proof "ath" mismatch');
  });

  it('fails when jkt thumbprint does not match accessTokenClaims.cnf.jkt', async () => {
    headers.dpop = await createProof(); // uses ES256 jwk
    const fn = verifyDPoP(
      createOptions({ accessTokenClaims: { cnf: { jkt: 'mismatch' } } as any })
    );
    await expect(fn).rejects.toThrow(InvalidTokenError);
    await expect(fn).rejects.toThrow('JWT Access Token confirmation mismatch');

    await expect(
      verifyDPoP(
        createOptions({ accessTokenClaims: { cnf: { jkt: '' } } as any })
      )
    ).rejects.toThrow(); // assertDPoPRequest would also catch empty jkt, but this ensures end check fails if it got here
  });

  it('passes across different supportedAlgorithms sets as long as alg is allowed', async () => {
    headers.dpop = await createProof(); // ES256
    await expect(
      verifyDPoP(createOptions({ supportedAlgorithms: ['ES256', 'ES384'] }))
    ).resolves.toBeUndefined();
  });

  it('throws InvalidTokenError when accessTokenClaims is undefined', async () => {
    headers.dpop = await createProof(); // ES256
    const options = createOptions({ supportedAlgorithms: ['ES256', 'ES384'] });
    (options.accessTokenClaims as any) = undefined;
    await expect(verifyDPoP(options)).rejects.toThrow(InvalidTokenError);
    await expect(verifyDPoP(options)).rejects.toThrow(
      'JWT Access Token confirmation mismatch'
    );
  });

  it('accepts additional custom claims in the payload (ignored for validation but preserved in output)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const proof = await createProof({
      // extra, non-standard claims
      foo: 'bar',
      aud: 'https://api.example.com',
      nbf: now - 10,
      exp: now + 300,
      nested: { a: 1, b: 'two' },
    });

    const { proofClaims } = await verifyProof(proof, ['ES256']);

    // Standard claims are present
    expect(proofClaims).toMatchObject({
      htm: method,
      htu: url,
      iat: expect.any(Number),
      jti: expect.any(String),
      ath: expect.any(String),
    });

    // Extra claims are carried through and do not cause errors
    expect(proofClaims.foo).toBe('bar');
    expect(proofClaims.aud).toBe('https://api.example.com');
    expect(typeof proofClaims.nbf).toBe('number');
    expect(typeof proofClaims.exp).toBe('number');
    expect(proofClaims.nested).toEqual({ a: 1, b: 'two' });
  });

  it('accepts additional protected header parameters (ignored for validation but preserved in output)', async () => {
    // Add benign extra header params alongside the required ones
    const proof = await createProof({}, {
      kid: 'kid123',
      cty: 'dpop+jwt',
      'x-extra': 'yes',
    } as any);

    const { proofHeader } = await verifyProof(proof, ['ES256']);

    // Required protected headers are there
    expect(proofHeader).toMatchObject({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: expect.any(Object),
    });

    // Extra header parameters are preserved and do not cause errors
    expect(proofHeader.kid).toBe('kid123');
    expect(proofHeader.cty).toBe('dpop+jwt');
    expect((proofHeader as any)['x-extra']).toBe('yes');
  });

  it('accepts extra fields in both payload and protected header at once', async () => {
    const proof = await createProof({ foo: 'payload-ok', arr: [1, 2, 3] }, {
      kid: 'kid-xyz',
      'x-extra': 'hdr-ok',
    } as any);

    const { proofClaims, proofHeader } = await verifyProof(proof, ['ES256']);

    // sanity
    expect(proofClaims.htm).toBe(method);
    expect(proofClaims.htu).toBe(url);

    // payload extras
    expect(proofClaims.foo).toBe('payload-ok');
    expect(proofClaims.arr).toEqual([1, 2, 3]);

    // header extras
    expect(proofHeader.kid).toBe('kid-xyz');
    expect((proofHeader as any)['x-extra']).toBe('hdr-ok');
  });
});
