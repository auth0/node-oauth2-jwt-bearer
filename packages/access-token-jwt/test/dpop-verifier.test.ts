import { verifyDPoP } from '../src/dpop-verifier';
import {
  InvalidRequestError,
  InvalidProofError,
  InvalidTokenError,
} from 'oauth2-bearer';
import {
  SignJWT,
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
} from 'jose';
import crypto from 'node:crypto';
import sinon from 'sinon';

describe('verifyDPoP (real proofs)', () => {
  let jwt: string;
  let jwk: any;
  let proof: string;
  let headers: Record<string, any>;
  let accessToken: string;
  let jkt: string;
  let url: string;
  let method: string;

  beforeEach(async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    jwk = await exportJWK(publicKey);
    accessToken = 'access.token.jwt';
    jkt = await calculateJwkThumbprint(jwk);
    method = 'GET';
    url = 'https://api.example.com/resource';

    const ath = crypto
      .createHash('sha256')
      .update(accessToken)
      .digest('base64url');

    proof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath,
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk,
      })
      .sign(privateKey);

    headers = {
      authorization: `DPoP ${accessToken}`,
      dpop: proof,
    };
    jwt = accessToken;
  });

  afterEach(() => {
    sinon.restore();
  });

  const validOptions = () => ({
    jwt,
    accessTokenClaims: { cnf: { jkt } },
    headers,
    method,
    url,
    supportedAlgorithms: ['ES256'],
    iatOffset: 300,
    iatLeeway: 60,
  });

  it('passes for a valid DPoP proof', async () => {
    await expect(verifyDPoP(validOptions())).resolves.not.toThrow();
  });

  it('throws if Authorization header is missing', async () => {
    delete headers.authorization;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws if Authorization scheme is not DPoP', async () => {
    headers.authorization = `Bearer ${jwt}`;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws if DPoP header is missing', async () => {
    delete headers.dpop;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws if Authorization header is empty', async () => {
    headers.authorization = '';
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws if DPoP header is not a string', async () => {
    (headers as any).dpop = 123;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws when dpop header is missing (branch coverage)', async () => {
    const jwt = 'abc.def.ghi';
  
    await expect(
      verifyDPoP({
        jwt,
        method: 'POST',
        url: 'https://api.example.com/resource',
        supportedAlgorithms: ['ES256'],
        iatOffset: 300,
        iatLeeway: 30,
        accessTokenClaims: { cnf: { jkt: 'xyz' } },
        headers: {
          authorization: `DPoP ${jwt}`,
          // ❌ dpop intentionally missing
        }
      })
    ).rejects.toThrow(InvalidRequestError);
  
    await expect(
      verifyDPoP({
        jwt,
        method: 'POST',
        url: 'https://api.example.com/resource',
        supportedAlgorithms: ['ES256'],
        iatOffset: 300,
        iatLeeway: 30,
        accessTokenClaims: { cnf: { jkt: 'xyz' } },
        headers: {} // ✅ clean way to hit `headers?.dpop === undefined`
      })
    ).rejects.toThrow(InvalidRequestError);
  });
  

  it('throws InvalidRequestError if Authorization header has invalid format', async () => {
    const result = verifyDPoP({
      jwt: 'abc.def.ghi',
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: 'DPoP ABC DEF',
        dpop: 'some-proof',
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: { jkt: 'some-thumbprint' },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidRequestError);
    await expect(result).rejects.toThrow(
      'Invalid Authorization HTTP Header format'
    );
  });

  it('throws if multiple DPoP headers are present', async () => {
    headers.dpop = `${proof},${proof}`;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(
      InvalidRequestError
    );
  });

  it('throws if jti is missing', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = badProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if typ header is incorrect', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'wrong', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = badProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws InvalidProofError if iat is missing in proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    // Sign a valid DPoP proof with NO `iat`
    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      jti: crypto.randomUUID(),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Missing "iat" claim in DPoP proof');
  });

  it('throws InvalidProofError if iat is outside the acceptable range', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    // Set iat to 10 minutes (600s) in the past — beyond the allowed offset of 5 minutes
    const outdatedIat = Math.floor(Date.now() / 1000) - 600;

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      jti: crypto.randomUUID(),
      iat: outdatedIat,
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300, // 5 minutes
      iatLeeway: 30, // 30 seconds
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow(
      'DPoP proof "iat" is outside the acceptable range'
    );
  });

  it('throws if ath does not match', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: 'tampered',
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = badProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if iat is in the future', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const futureProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000) + 1000,
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = futureProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if htm does not match', async () => {
    method = 'POST';
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if htu does not match', async () => {
    url = 'https://wrong.example.com/resource';
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if jwk is missing in header', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const noJwkProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256' })
      .sign(privateKey);

    headers.dpop = noJwkProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if jkt does not match', async () => {
    const badJkt = 'invalid-thumbprint';
    await expect(
      verifyDPoP({
        ...validOptions(),
        accessTokenClaims: { cnf: { jkt: badJkt } },
      })
    ).rejects.toThrow(InvalidTokenError);
  });

  it('throws InvalidRequestError if jkt confirmation claim is missing or invalid', async () => {
    const result = verifyDPoP({
      jwt: 'abc.def.ghi',
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: 'DPoP abc.def.ghi',
        dpop: 'some-proof',
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: { jkt: undefined as any },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidRequestError);
    await expect(result).rejects.toThrow(
      'Operation indicated DPoP use but the JWT Access Token has no jkt confirmation claim'
    );
  });

  it('throws if DPoP proof has a tampered payload (invalid signature)', async () => {
    const parts = proof.split('.');
    const tamperedPayload = Buffer.from(
      JSON.stringify({
        ...JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
        htm: 'POST', // change method to tamper the payload
      })
    ).toString('base64url');

    // Reconstruct the JWT with tampered payload and original header/signature
    headers.dpop = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if accessToken is missing', async () => {
    const opts = validOptions();
    delete (opts as any).jwt;
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidTokenError);
  });

  it('throws if DPoP proof is expired', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const expiredProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000) - 1000,
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = expiredProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if DPoP proof uses an unsupported algorithm', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const unsupportedProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'RS256',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    headers.dpop = unsupportedProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if DPoP proof has an invalid signature', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const invalidSignatureProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    // Tamper with the proof to invalidate the signature
    headers.dpop = invalidSignatureProof + 'tampered';
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if DPoP proof contains additional unexpected claims', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const extraClaimsProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
      extraClaim: 'unexpected', // Additional claim
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = extraClaimsProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });
  // This test case is not applicable in this context as it requires jti caching to be implemented.
  // it('throws if DPoP proof is reused (replay attack)', async () => {
  //   const opts = validOptions();
  //   await expect(verifyDPoP(opts)).resolves.not.toThrow(); // First use should pass
  //   a
  // wait expect(verifyDPoP(opts)).rejects.toThrow(InvalidProofError); // Replay should fail
  // });

  it('throws if DPoP proof has a malformed header', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const malformedHeaderProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: { kty: 'EC', crv: 'P-256', x: 'invalid-x', y: 'invalid-y' },
      })
      .sign(privateKey);

    headers.dpop = malformedHeaderProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if accessTokenClaims is missing', async () => {
    const opts = validOptions();
    delete (opts as any).accessTokenClaims;
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidTokenError);
  });

  it('throws if cnf is not an object', async () => {
    const opts = validOptions();
    opts.accessTokenClaims = { cnf: 'not-an-object' as any };
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidRequestError);
  });

  it('throws if cnf contains multiple keys', async () => {
    const opts = validOptions();
    opts.accessTokenClaims = { cnf: { jkt, extra: 'value' } as any };
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidRequestError);
  });

  it('throws if jkt in cnf is missing or empty', async () => {
    const opts = validOptions();
    opts.accessTokenClaims = { cnf: { jkt: '' } };
    await expect(verifyDPoP(opts)).rejects.toThrow(InvalidRequestError);
  });

  it('throws if iat is not a number', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const malformedProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: 'invalid' as any,
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = malformedProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if headers is undefined', async () => {
    await expect(
      verifyDPoP({ ...validOptions(), headers: undefined as any })
    ).rejects.toThrow(InvalidRequestError);
  });

  it('throws if headers is not an object', async () => {
    await expect(
      verifyDPoP({ ...validOptions(), headers: 'not-an-object' as any })
    ).rejects.toThrow(InvalidRequestError);
  });

  it('throws if typ header is missing', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ alg: 'ES256', jwk }) // missing typ
      .sign(privateKey);

    headers.dpop = badProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if dpop is not a valid JWT format', async () => {
    headers.dpop = 'invalid.token';
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if jwk is not an object', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const malformedJwkProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: 'not-object' as any,
      })
      .sign(privateKey);

    headers.dpop = malformedJwkProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws if alg is not in supportedAlgorithms list', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const rs256Jwk = await exportJWK(publicKey);

    const badAlgProof = await new SignJWT({
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'RS256', jwk: rs256Jwk })
      .sign(privateKey);

    headers.dpop = badAlgProof;
    await expect(
      verifyDPoP({
        ...validOptions(),
        headers,
        supportedAlgorithms: ['ES256'], // RS256 is NOT supported here
      })
    ).rejects.toThrow(InvalidProofError);
  });

  it('throws if htu is not a string', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badHtuProof = await new SignJWT({
      htm: method,
      htu: 123 as any,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = badHtuProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws InvalidRequestError if request URL is malformed', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const malformedRequestUrl = 'ht!tp:/invalid-url'; // malformed URL that will break `new URL(url)`

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: malformedRequestUrl,
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidRequestError);
    await expect(result).rejects.toThrow('Invalid request URL');
  });

  it('throws InvalidProofError if htu in proof is malformed', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    // Sign a valid DPoP proof with a malformed htu
    const malformedHtu = 'ht!tp:/invalid-url';
    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: malformedHtu,
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Invalid htu claim URL');
  });

  it('throws if htm is not a string', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const badHtmProof = await new SignJWT({
      htm: 123 as any,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: crypto.createHash('sha256').update(jwt).digest('base64url'),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
      .sign(privateKey);

    headers.dpop = badHtmProof;
    await expect(verifyDPoP(validOptions())).rejects.toThrow(InvalidProofError);
  });

  it('throws InvalidProofError if htm is missing in DPoP proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      // htm intentionally omitted
      htu: 'https://api.example.com/resource',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Missing "htm" in DPoP proof');
  });

  it('throws InvalidProofError if htm is not a string in DPoP proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 12345 as any, // invalid type
      htu: 'https://api.example.com/resource',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Invalid "htm" claim');
  });

  it('throws InvalidProofError if htu is missing in DPoP proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      // htu is intentionally omitted
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Missing "htu" in DPoP proof');
  });

  it('throws InvalidProofError if "htu" claim is not a string', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 12345 as any, // invalid type
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Invalid "htu" claim');
  });

  it('throws InvalidProofError if "jti" claim is missing in DPoP proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';
    const encodedAth = crypto
      .createHash('sha256')
      .update(jwt)
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      iat: Math.floor(Date.now() / 1000),
      ath: encodedAth,
      // jti is intentionally omitted
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Missing "jti" in DPoP proof');
  });

  it('throws InvalidProofError if "ath" claim is missing in DPoP proof', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature'; // access token placeholder

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      // ath is intentionally omitted
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Missing "ath" claim in DPoP proof');
  });

  it('throws InvalidProofError if "ath" claim is not a string', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: 12345 as any,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('Invalid "ath" claim');
  });

  it('throws InvalidProofError if "ath" claim does not match the hash of the access token', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');

    const jwt = 'header.payload.signature';

    const mismatchedAth = crypto
      .createHash('sha256')
      .update('some-other-token')
      .digest('base64url');

    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://api.example.com/resource',
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      ath: mismatchedAth, // Incorrect "ath"
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'dpop+jwt',
        jwk: await exportJWK(publicKey),
      })
      .sign(privateKey);

    const result = verifyDPoP({
      jwt,
      method: 'POST',
      url: 'https://api.example.com/resource',
      headers: {
        authorization: `DPoP ${jwt}`,
        dpop: proof,
      },
      supportedAlgorithms: ['ES256'],
      accessTokenClaims: {
        cnf: {
          jkt: await calculateJwkThumbprint(await exportJWK(publicKey)),
        },
      },
      iatOffset: 300,
      iatLeeway: 30,
    });

    await expect(result).rejects.toThrow(InvalidProofError);
    await expect(result).rejects.toThrow('DPoP Proof "ath" mismatch');
  });
});
