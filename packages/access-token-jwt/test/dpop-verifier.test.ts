import {
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
} from 'oauth2-bearer';

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

describe('normalizeUrl', () => {
  it('removes query and fragment from URL', () => {
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

  it('preserves username and password in URL', () => {
    const raw = 'https://user:pass@api.example.com/resource?foo=bar';
    const expected = 'https://user:pass@api.example.com/resource';
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
    expect(() => normalizeUrl(malformed, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(malformed, 'request')).toThrow('Invalid request URL');
  });

  it('throws InvalidProofError if proof htu is invalid', () => {
    const malformed = ':://foo.bar?x=1';
    expect(() => normalizeUrl(malformed, 'proof')).toThrow(InvalidProofError);
    expect(() => normalizeUrl(malformed, 'proof')).toThrow('Invalid htu claim URL');
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

  it('should strip query and fragment', () => {
    const input = 'https://api.example.com/path?query=value#fragment';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  it('should normalize full complex URL with auth, port, dot segments, and fragment', () => {
    const input =
      'HTTPS://USER:PASS@API.EXAMPLE.COM:443/path/../RESOURCE/./file.txt?query=value#fragment';
    const expected = 'https://USER:PASS@api.example.com/RESOURCE/file.txt';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
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
    msgIncludes?: string
  ) => {
    try {
      assertDPoPRequest(headers, claims);
      throw new Error('Expected assertDPoPRequest to throw');
    } catch (err: any) {
      expect(err).toBeInstanceOf(InvalidRequestError);
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
    expectFail(
      headers,
      validClaims(),
      'Operation indicated DPoP use but the request is missing an Authorization HTTP Header'
    );
  });

  it('fails when Authorization is null', () => {
    const headers = baseHeaders();
    headers.authorization = null as any;
    expectFail(
      headers,
      validClaims(),
      'Operation indicated DPoP use but the request is missing an Authorization HTTP Header'
    );
  });

  it('fails when Authorization is not a string', () => {
    const headers = baseHeaders();
    headers.authorization = 123 as any;
    expectFail(
      headers,
      validClaims(),
      "Operation indicated DPoP use but the request's Authorization HTTP Header is malformed"
    );
  });

  it('fails when Authorization scheme is not DPoP (Bearer)', () => {
    const headers = baseHeaders();
    headers.authorization = `Bearer ${jwt}`;
    expectFail(
      headers,
      validClaims(),
      "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"
    );
  });

  it('fails when Authorization header has too many parts', () => {
    const headers = baseHeaders();
    headers.authorization = 'DPoP abc def';
    expectFail(
      headers,
      validClaims(),
      'Invalid Authorization HTTP Header format'
    );
  });

  it('fails when DPoP header is missing', () => {
    const headers = baseHeaders();
    delete headers.dpop;
    expectFail(
      headers,
      validClaims(),
      'Operation indicated DPoP use but the request has no DPoP HTTP Header'
    );
  });

  it('fails when DPoP header is not a string', () => {
    const headers = baseHeaders();
    headers.dpop = { not: 'a string' } as any;
    expectFail(headers, validClaims(), 'DPoP HTTP Header must be a string');
  });

  it('fails when multiple DPoP headers are provided (comma-separated)', () => {
    const headers = baseHeaders();
    headers.dpop = 'proof1,proof2';
    expectFail(headers, validClaims(), 'Multiple DPoP headers are not allowed');
  });

  it('fails when accessTokenClaims.cnf is missing', () => {
    expectFail(
      baseHeaders(),
      {},
      'Operation indicated DPoP use but the JWT Access Token has no confirmation claim'
    );
  });

  it('fails when cnf is not an object (string)', () => {
    expectFail(
      baseHeaders(),
      { cnf: 'bad' },
      'Invalid "cnf" confirmation claim structure'
    );
  });

  it('fails when cnf is an array', () => {
    expectFail(
      baseHeaders(),
      { cnf: [] },
      'Invalid "cnf" confirmation claim structure'
    );
  });

  it('fails when cnf contains multiple keys', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: 'thumb', extra: 'x' } },
      'Multiple confirmation claims are not supported'
    );
  });

  it('fails when cnf.jkt is missing (undefined)', () => {
    expectFail(
      baseHeaders(),
      { cnf: {} },
      'Operation indicated DPoP use but the JWT Access Token has no jkt confirmation claim'
    );
  });

  it('fails when cnf.jkt is not a string', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: 123 } },
      'Malformed "jkt" confirmation claim'
    );
  });

  it('fails when cnf.jkt is an empty string', () => {
    expectFail(
      baseHeaders(),
      { cnf: { jkt: '' } },
      'Invalid "jkt" confirmation claim'
    );
  });

  it('passes when cnf.jkt is a non-empty string', () => {
    expectPass(baseHeaders(), { cnf: { jkt: 'abc' } });
  });

  it('fails early with a clear message when headers is an empty object', () => {
    expectFail(
      {},
      validClaims(),
      'Operation indicated DPoP use but the request is missing an Authorization HTTP Header'
    );
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
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidRequestError);
  });

  it('fails when access token (jwt) is missing', async () => {
    headers.dpop = await createProof();
    const opts = createOptions();
    delete (opts as any).jwt;
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidTokenError);
    await expect(verifyDPoP({ ...opts, jwt: 123 as any })).rejects.toThrow(
      InvalidTokenError
    );
  });

  it('fails if verifyProof rejects (unsupported alg or malformed proof)', async () => {
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
    await expect(
      verifyDPoP(createOptions({ supportedAlgorithms: ['ES256'] }))
    ).rejects.toThrow(InvalidProofError);
  });

  it('fails when iat is missing', async () => {
    headers.dpop = await createProof({ iat: undefined });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      'Missing "iat" claim in DPoP proof'
    );
  });

  it('fails when iat is not a number', async () => {
    headers.dpop = await createProof({ iat: 'bad' as any });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      '"iat" claim must be a number'
    );
  });

  it('fails when iat is outside acceptable range (too old)', async () => {
    headers.dpop = await createProof({
      iat: Math.floor(Date.now() / 1000) - 1000,
    });
    await expect(
      verifyDPoP(createOptions({ iatOffset: 300, iatLeeway: 60 }))
    ).rejects.toThrow('DPoP proof "iat" is outside the acceptable range');
  });

  it('fails when iat is outside acceptable range (in future)', async () => {
    headers.dpop = await createProof({
      iat: Math.floor(Date.now() / 1000) + 1000,
    });
    await expect(
      verifyDPoP(createOptions({ iatOffset: 300, iatLeeway: 60 }))
    ).rejects.toThrow('DPoP proof "iat" is outside the acceptable range');
  });

  it('fails when htm is missing', async () => {
    headers.dpop = await createProof({ htm: undefined });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      'Missing "htm" in DPoP proof'
    );
  });

  it('fails when htm is not a string', async () => {
    headers.dpop = await createProof({ htm: 123 as any });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      'Invalid "htm" claim'
    );
  });

  it('fails when htm does not match request method', async () => {
    headers.dpop = await createProof({ htm: 'POST' });
    await expect(verifyDPoP(createOptions({ method: 'GET' }))).rejects.toThrow(
      'DPoP Proof htm mismatch'
    );
  });

  it('fails when htu is missing', async () => {
    headers.dpop = await createProof({ htu: undefined });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      'Missing "htu" in DPoP proof'
    );
  });

  it('fails when htu is not a string', async () => {
    headers.dpop = await createProof({ htu: 123 as any });
    await expect(verifyDPoP(createOptions())).rejects.toThrow(
      'Invalid "htu" claim'
    );
  });

  it('fails when normalized htu does not match request URL', async () => {
    headers.dpop = await createProof({ htu: 'https://api.example.com/other' });
    await expect(
      verifyDPoP(createOptions({ url: 'https://api.example.com/resource' }))
    ).rejects.toThrow('DPoP Proof htu mismatch');
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
});
