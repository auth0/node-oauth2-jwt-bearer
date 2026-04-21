import { randomBytes } from 'crypto';
import nock from 'nock';
import sinon from 'sinon';
import { createJwt, createJwtWithKey, now } from './helpers';
import { jwtVerifier, InvalidTokenError } from '../src';
import validate from '../src/validate.js';

describe('jwt-verifier', () => {
  afterEach(nock.cleanAll);

  it('should throw when configured with no jwksUri or issuerBaseURL and issuer', async () => {
    expect(() =>
      jwtVerifier({
        audience: 'https://api/',
      })
    ).toThrowError(
      "You must provide 'mcd', 'issuerBaseURL', or both 'issuer' and ('jwksUri', 'secret', or 'publicKey')"
    );
  });

  it('should throw when configured with no audience', async () => {
    expect(() =>
      jwtVerifier({
        jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
        issuer: 'https://issuer.example.com/',
      })
    ).toThrowError("An 'audience' is required to validate the 'aud' claim");
  });

  it('should throw when configured with secret and no token signing alg', async () => {
    expect(() =>
      jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: randomBytes(32).toString('hex'),
      })
    ).toThrowError(
      "You must provide a 'tokenSigningAlg' for validating symmetric algorithms"
    );
  });

  it('should throw when configured with secret and invalid token signing alg', async () => {
    expect(() =>
      jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: randomBytes(32).toString('hex'),
        tokenSigningAlg: 'none',
      })
    ).toThrowError(
      "You must supply one of HS256, HS384, HS512 for 'tokenSigningAlg' to validate symmetrically signed tokens"
    );
  });

  it('should throw when configured with JWKS uri and invalid token signing alg', async () => {
    expect(() =>
      jwtVerifier({
        jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        tokenSigningAlg: 'none',
      })
    ).toThrowError(
      "You must supply one of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES256K, ES384, ES512, EdDSA for 'tokenSigningAlg' to validate asymmetrically signed tokens"
    );
  });

  it('should verify the token', async () => {
    const jwt = await createJwt();

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toHaveProperty('payload', {
      iss: 'https://issuer.example.com/',
      sub: 'me',
      aud: 'https://api/',
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
  });

  it('should throw for unexpected issuer', async () => {
    const jwt = await createJwt({
      issuer: 'https://issuer1.example.com/',
    });

    const verify = jwtVerifier({
      jwksUri: 'https://issuer1.example.com/.well-known/jwks.json',
      issuer: 'https://issuer2.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).rejects.toThrowError(`Unexpected 'iss' value`);
  });

  it('should throw for unexpected audience', async () => {
    const jwt = await createJwt({
      audience: 'https://api1/',
    });

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api2/',
    });
    await expect(verify(jwt)).rejects.toThrowError(`Unexpected 'aud' value`);
  });

  it('should throw for an expired token', async () => {
    const jwt = await createJwt({
      exp: now - 10,
    });

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).rejects.toThrowError(
      '"exp" claim timestamp check failed'
    );
  });

  it('should throw for invalid nbf', async () => {
    const clock = sinon.useFakeTimers(1000);
    const jwt = await createJwt({
      payload: {
        nbf: 2000,
      },
    });

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).rejects.toThrowError(
      '"nbf" claim timestamp check failed'
    );
    clock.restore();
  });

  it('should validate nbf claim with clockTolerance', async () => {
    const clock = sinon.useFakeTimers(1000);
    const jwt = await createJwt({
      payload: {
        nbf: 2000,
      },
    });

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
      clockTolerance: 5000,
    });
    await expect(verify(jwt)).resolves.not.toThrow();
    clock.restore();
  });

  it('should throw unexpected token signing alg', async () => {
    const secret = randomBytes(32).toString('hex');
    const jwt = await createJwt({ secret });

    const verify = jwtVerifier({
      secret,
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
      tokenSigningAlg: 'HS384',
    });
    await expect(verify(jwt)).rejects.toThrowError("Unexpected 'alg' value");
  });

  it('should fail with invalid_token error', async () => {
    const jwt = await createJwt({
      issuer: 'https://issuer.example.com',
    });
    const verify = jwtVerifier({
      issuerBaseURL:
        'https://issuer.example.com/.well-known/openid-configuration',
      audience: 'https://api/',
    });
    await expect(verify(`CORRUPT-${jwt}`)).rejects.toThrow(InvalidTokenError);
  });

  it('should honor configured cache max age', async () => {
    const clock = sinon.useFakeTimers({
      toFake: ['Date'],
    });
    const jwksSpy = jest.fn();
    const discoverSpy = jest.fn();
    const jwt = await createJwt({
      jwksSpy,
      discoverSpy,
    });

    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 10,
    });
    await expect(verify(jwt)).resolves.toHaveProperty('payload');
    await expect(verify(jwt)).resolves.toHaveProperty('payload');
    expect(jwksSpy).toHaveBeenCalledTimes(1);
    expect(discoverSpy).toHaveBeenCalledTimes(1);
    clock.tick(11);
    await expect(verify(jwt)).resolves.toHaveProperty('payload');
    expect(jwksSpy).toHaveBeenCalledTimes(2);
    expect(discoverSpy).toHaveBeenCalledTimes(2);
    clock.restore();
  });

  it('should not cache failed requests', async () => {
    nock('https://issuer.example.com/')
      .get('/.well-known/openid-configuration')
      .reply(500)
      .get('/.well-known/jwks.json')
      .reply(500);

    const jwt = await createJwt();

    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 10,
    });
    await expect(verify(jwt)).rejects.toThrowError(
      /Failed to fetch authorization server metadata/
    );
    await expect(verify(jwt)).rejects.toThrowError(
      /Expected 200 OK from the JSON Web Key Set HTTP response/
    );
    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should honor custom cache.discovery maxEntries configuration', async () => {
    const jwt = await createJwt();

    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cache: {
        discovery: {
          maxEntries: 2, // Only cache 2 issuers
          ttl: 60000,
        },
      },
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should honor custom cache.jwks maxEntries configuration', async () => {
    const jwt = await createJwt();

    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cache: {
        jwks: {
          maxEntries: 2, // Only cache 2 JWKS
          ttl: 60000,
        },
      },
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should use default cache settings when cache option not provided', async () => {
    const jwt = await createJwt();

    // No cache configuration = defaults apply (100 entries, 10 min TTL)
    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should fall back to deprecated cacheMaxAge when cache config not provided', async () => {
    const jwt = await createJwt();

    // Using deprecated cacheMaxAge (backward compatibility)
    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 300000, // 5 minutes
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should prioritize cache.discovery.ttl over deprecated cacheMaxAge', async () => {
    const jwt = await createJwt();

    // New cache config should override deprecated cacheMaxAge
    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 300000, // Should be ignored
      cache: {
        discovery: {
          ttl: 120000, // 2 minutes - should be used
        },
      },
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should use cacheMaxAge when cache object provided but discovery.ttl not specified', async () => {
    const jwt = await createJwt();

    // cache object exists but discovery.ttl is not specified
    // Should fall back to cacheMaxAge
    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 300000, // Should be used as fallback
      cache: {
        jwks: {
          ttl: 120000,
        },
      },
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  it('should use cacheMaxAge when cache.discovery provided but ttl not specified', async () => {
    const jwt = await createJwt();

    // cache.discovery exists but ttl is not specified
    // Should fall back to cacheMaxAge
    const verify = jwtVerifier({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
      cacheMaxAge: 300000, // Should be used as fallback
      cache: {
        discovery: {
          maxEntries: 50,
          // ttl not specified
        },
      },
    });

    await expect(verify(jwt)).resolves.toHaveProperty('payload');
  });

  // MCD Tests
  describe('MCD (Multiple Custom Domains)', () => {
    it('should throw when both mcd and issuerBaseURL are provided', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: ['https://tenant1.auth0.com'],
          },
          issuerBaseURL: 'https://tenant1.auth0.com',
          audience: 'https://api/',
        })
      ).toThrowError(
        "You must not provide both 'mcd' and 'issuerBaseURL'"
      );
    });

    it('should throw when mcd is provided without issuers', () => {
      expect(() =>
        jwtVerifier({
          mcd: {} as any,
          audience: 'https://api/',
        })
      ).toThrowError("Invalid MCD configuration: 'issuers' is required");
    });

    it('should throw when both mcd and issuer are provided', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: ['https://tenant1.auth0.com'],
          },
          issuer: 'https://tenant1.auth0.com',
          jwksUri: 'https://tenant1.auth0.com/.well-known/jwks.json',
          audience: 'https://api/',
        })
      ).toThrowError(
        "You must not provide both 'mcd' and 'issuer'. Use 'mcd' for multi-issuer mode."
      );
    });

    it('should throw when both mcd and jwksUri are provided', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: ['https://tenant1.auth0.com'],
          },
          jwksUri: 'https://tenant1.auth0.com/.well-known/jwks.json',
          audience: 'https://api/',
        })
      ).toThrowError(
        "You must not provide both 'mcd' and 'jwksUri'. Use 'mcd' for multi-issuer mode."
      );
    });

    it('should throw when both mcd and secret are provided', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: ['https://tenant1.auth0.com'],
          },
          secret: 'my-secret',
          audience: 'https://api/',
        })
      ).toThrowError(
        'Cannot use top-level "secret" with mcd mode. ' +
        'Specify secrets per-issuer in the issuer configuration: ' +
        '{ issuer: "...", secret: "...", alg: "HS256" }'
      );
    });

    // Initialization-time validation tests
    it('should throw at init when symmetric algorithm configured without secret', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.auth0.com',
                alg: 'HS256', // Symmetric algorithm
                // No secret provided!
              },
            ],
          },
          audience: 'https://api/',
        })
      ).toThrowError(
        "Configuration error: Issuer 'https://tenant1.auth0.com' specifies symmetric algorithm 'HS256' but no secret provided"
      );
    });

    it('should throw at init when secret provided with asymmetric algorithm', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.auth0.com',
                alg: 'RS256', // Asymmetric algorithm
                secret: 'my-secret', // Secret provided!
              },
            ],
          },
          audience: 'https://api/',
        })
      ).toThrowError(
        "Configuration error: Issuer 'https://tenant1.auth0.com' provides a secret but specifies asymmetric algorithm 'RS256'"
      );
    });

    it('should throw at init when secret provided without algorithm', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.auth0.com',
                secret: 'my-secret', // Secret but no alg
              },
            ],
          },
          audience: 'https://api/',
        })
      ).toThrowError(
        "Configuration error: Issuer 'https://tenant1.auth0.com' provides a secret but no 'alg' specified"
      );
    });

    it('should not throw when string-only issuer configs used (no algorithm specified)', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: ['https://tenant1.auth0.com', 'https://tenant2.auth0.com'],
          },
          audience: 'https://api/',
        })
      ).not.toThrow();
    });

    it('should not throw when valid symmetric config provided', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.auth0.com',
                alg: 'HS256',
                secret: 'my-secret', // Valid!
              },
            ],
          },
          audience: 'https://api/',
        })
      ).not.toThrow();
    });

    it('should not validate dynamic resolvers at init time', () => {
      // Dynamic resolver - can return anything at runtime
      // Should not throw at initialization
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: async () => {
              // Could return invalid config at runtime, but we can't check now
              return [
                {
                  issuer: 'https://tenant1.auth0.com',
                  alg: 'HS256',
                  // No secret - but this is not validated at init time
                },
              ];
            },
          },
          audience: 'https://api/',
        })
      ).not.toThrow();
    });

    it('should verify token with MCD static issuer (string)', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload', {
        iss: 'https://tenant1.example.com/',
        sub: 'me',
        aud: 'https://api/',
        iat: expect.any(Number),
        exp: expect.any(Number),
      });
    });

    it('should verify token with MCD static issuers array', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant2.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            'https://tenant1.example.com/',
            'https://tenant2.example.com/',
            'https://tenant3.example.com/',
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should verify token with MCD issuer config object (asymmetric)', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              alg: 'RS256',
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should verify token with MCD issuer config with custom jwksUri', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/custom-jwks',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              jwksUri: 'https://tenant1.example.com/custom-jwks',
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should verify token with MCD symmetric issuer config', async () => {
      const secret = randomBytes(32).toString('hex');
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret,
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              alg: 'HS256',
              secret,
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should throw when token issuer not in MCD allowed list', async () => {
      const jwt = await createJwt({
        issuer: 'https://unauthorized.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            'https://tenant1.example.com/',
            'https://tenant2.example.com/',
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Token issuer is not allowed"
      );
    });

    it('should throw when token missing iss claim in MCD mode', async () => {
      // Manually create a token without iss claim
      const { generateKeyPair, SignJWT } = require('jose');
      const { privateKey } = await generateKeyPair('RS256');
      const jwtWithoutIss = await new SignJWT({})
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'kid' })
        .setAudience('https://api/')
        .setIssuedAt(now)
        .setExpirationTime(now + 86400)
        .sign(privateKey);

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwtWithoutIss)).rejects.toThrowError(
        "Token missing required 'iss' claim"
      );
    });

    it('should normalize issuer URLs in MCD mode', async () => {
      // Token with uppercase and default port
      const jwt = await createJwt({
        issuer: 'https://TENANT1.EXAMPLE.COM:443/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      // Config with normalized URL
      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should work with MCD dynamic resolver function', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async (context) => {
            // Dynamic resolver that returns allowed issuers as strings (currently supported)
            return ['https://tenant1.example.com/', 'https://tenant2.example.com/'];
          },
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should work with MCD dynamic resolver returning single string', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async (context) => {
            return ['https://tenant1.example.com/'];
          },
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should throw when empty issuers array provided at runtime', async () => {
      // Manually create a token header for testing
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        iss: 'https://tenant1.example.com/',
        aud: 'https://api/',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      })).toString('base64url');
      const fakeJwt = `${header}.${payload}.fake-signature`;

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [], // Returns empty array
        },
        audience: 'https://api/',
      });

      await expect(verify(fakeJwt)).rejects.toThrowError(
        'No issuers configured for token validation'
      );
    });

    it('should reject algorithm "none" early', async () => {
      // Manually create a token with alg: "none"
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        iss: 'https://tenant1.example.com/',
        aud: 'https://api/',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      })).toString('base64url');
      const fakeJwt = `${header}.${payload}.`; // No signature for "none" alg

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(fakeJwt)).rejects.toThrowError(
        'Unsupported algorithm "none" for JWKS-based verification'
      );
    });

    it('should reject RS256 token when expecting symmetric algorithm with secret', async () => {
      // Create an RS256 token
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              alg: 'HS256',
              secret: 'my-secret', // Secret configured, so expects HS* algorithms
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Unsupported algorithm "RS256" for secret-based verification. Supported: HS256, HS384, HS512'
      );
    });

    it('should reject HS256 token when no secret configured', async () => {
      const secret = 'my-secret-key';
      // Create an HS256 token
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret,
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              // No secret configured, so expects asymmetric algorithms only
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Unsupported algorithm "HS256" for JWKS-based verification. Supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES256K, ES384, ES512, EdDSA'
      );
    });

    it('should throw InvalidTokenError (not raw SyntaxError) for malformed JWT header', async () => {
      // A JWT whose header segment is not valid base64url-encoded JSON.
      // Previously JSON.parse threw SyntaxError and leaked the raw message; now
      // decodeProtectedHeader from jose surfaces a clean, structured error instead.
      const malformedJwt = '!!!notbase64!!!.payload.signature';

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(malformedJwt)).rejects.toBeInstanceOf(InvalidTokenError);
      await expect(verify(malformedJwt)).rejects.not.toThrow(
        expect.stringContaining('SyntaxError')
      );
    });

    it('should reject token with missing alg header', async () => {
      // Manually create a token header without 'alg' field
      const headerWithoutAlg = Buffer.from(JSON.stringify({ typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        iss: 'https://tenant1.example.com/',
        aud: 'https://api/',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      })).toString('base64url');
      const fakeJwt = `${headerWithoutAlg}.${payload}.fake-signature`;

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(fakeJwt)).rejects.toThrowError(
        'Token header missing or invalid "alg" claim'
      );
    });

    it('should work with MCD dynamic resolver returning config objects', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async (context) => {
            return [
              {
                issuer: 'https://tenant1.example.com/',
                alg: 'RS256',
              },
            ];
          },
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should pass token claims to dynamic resolver', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        payload: { org_id: 'org123' },
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const resolverSpy = jest.fn().mockResolvedValue(['https://tenant1.example.com/']);

      const verify = jwtVerifier({
        mcd: {
          issuers: resolverSpy,
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');

      expect(resolverSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          url: expect.any(URL),
          headers: expect.any(Object),
        })
      );
    });

    it('should handle MCD with mixed string and config in static array', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            'https://tenant1.example.com/',
            {
              issuer: 'https://tenant2.example.com/',
              alg: 'RS256',
            },
          ] as any,
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should throw error when no JWKS URI available in MCD mode', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      // Create a config without jwksUri and without discovery
      nock.cleanAll(); // Clear existing nock mocks
      nock('https://tenant1.example.com/')
        .get('/.well-known/openid-configuration')
        .reply(404)
        .get('/.well-known/oauth-authorization-server')
        .reply(404)
        .get('/.well-known/oauth-authorization-server/tenant1.example.com')
        .reply(404);

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError();
    });

    it('should normalize issuer with non-default HTTPS port', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com:8443/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com:8443'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should normalize issuer with non-default HTTP port', async () => {
      const jwt = await createJwt({
        issuer: 'http://tenant1.example.com:8080/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: ['http://tenant1.example.com:8080'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should verify token with MCD single issuer string (not array)', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: 'https://tenant1.example.com/', // Single string, not array
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should normalize issuer with pathname', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/auth/tenant1/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/auth/tenant1'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should handle malformed issuer URL gracefully in normalization', async () => {
      // Create token with valid issuer first
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      // Use a resolver that returns a malformed URL
      // The normalization catch block will return it as-is
      const verify = jwtVerifier({
        mcd: {
          issuers: async () => {
            // This will trigger the catch block in normalizeIssuerUrl
            // because it's not a valid URL format
            return [':::invalid:::url:::'];
          },
        },
        audience: 'https://api/',
      });

      // Will fail to match because normalized token issuer won't match malformed config issuer
      await expect(verify(jwt)).rejects.toThrowError(
        "Token issuer is not allowed"
      );
    });

    it('should normalize issuer without protocol by prepending https://', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      // Config WITHOUT protocol
      const verify = jwtVerifier({
        mcd: {
          issuers: ['tenant1.example.com'], // No https://
        },
        audience: 'https://api/',
      });

      // Should match because normalization prepends https://
      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should normalize issuer without protocol and with trailing slash', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      // Config WITHOUT protocol but WITH trailing slash
      const verify = jwtVerifier({
        mcd: {
          issuers: ['tenant1.example.com/'], // No https:// but has /
        },
        audience: 'https://api/',
      });

      // Should match because normalization prepends https:// and removes trailing slash
      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should throw error when neither secret nor jwksUri available after failed discovery', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      // Clear all mocks to prevent discovery from succeeding
      nock.cleanAll();
      nock('https://tenant1.example.com/')
        .get('/.well-known/openid-configuration')
        .reply(404)
        .get('/.well-known/oauth-authorization-server')
        .reply(404)
        .get('/.well-known/oauth-authorization-server/tenant1.example.com')
        .reply(404);

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              // No jwksUri, no secret - will fail
            } as any,
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Failed to fetch authorization server metadata'
      );
    });

    it('should throw error when discovery returns no jwks_uri', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      // Mock discovery to return metadata without jwks_uri
      nock.cleanAll();
      nock('https://tenant1.example.com/')
        .get('/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://tenant1.example.com/',
          // Missing jwks_uri!
        });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              // No custom jwksUri, no secret - discovery returns no jwks_uri
            } as any,
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'No JWKS URI, public key, or secret available for verification'
      );
    });

    it('should reject symmetric algorithm (HS256) without secret configured', async () => {
      const secret = randomBytes(32).toString('hex');
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret, // Token is signed with HS256
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              // No secret configured - should reject HS* algorithms
            } as any,
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Unsupported algorithm "HS256" for JWKS-based verification. Supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES256K, ES384, ES512, EdDSA'
      );
    });

    it('should throw when discovery issuer does not match token issuer', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      // Mock discovery to return different issuer
      nock.cleanAll();
      nock('https://tenant1.example.com/')
        .get('/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://different-tenant.example.com/', // Mismatch!
          jwks_uri: 'https://tenant1.example.com/.well-known/jwks.json',
        });

      const verify = jwtVerifier({
        mcd: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Discovery metadata issuer does not match token issuer"
      );
    });

    it('should work with dynamic resolver when no request context provided', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const resolverSpy = jest.fn().mockResolvedValue(['https://tenant1.example.com/']);

      const verify = jwtVerifier({
        mcd: {
          issuers: resolverSpy,
        },
        audience: 'https://api/',
      });

      // Call without request context
      await expect(verify(jwt)).resolves.toHaveProperty('payload');

      // Verify resolver was called with default values
      expect(resolverSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          url: expect.any(URL), // Should be http://localhost
          headers: {}, // Should be empty object
        })
      );
    });

    it('should pass real request context to dynamic resolver', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const resolverSpy = jest.fn().mockResolvedValue(['https://tenant1.example.com/']);

      const verify = jwtVerifier({
        mcd: {
          issuers: resolverSpy,
        },
        audience: 'https://api/',
      });

      // Call WITH request context
      await expect(
        verify(jwt, {
          url: 'https://api.example.com/resource',
          headers: { 'x-tenant-id': 'tenant1', authorization: 'Bearer ...' },
        })
      ).resolves.toHaveProperty('payload');

      // Verify resolver received actual request context
      expect(resolverSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          url: new URL('https://api.example.com/resource'),
          headers: { 'x-tenant-id': 'tenant1', authorization: 'Bearer ...' },
        })
      );
    });

    it('should throw when dynamic resolver returns non-array', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => 'not-an-array' as any, // Returns string instead of array
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Issuer resolver function must return an array'
      );
    });

    it('should work when dynamic resolver returns strings (backward compatibility)', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => ['https://tenant1.example.com/'], // String arrays still supported
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should reject when dynamic resolver returns config with symmetric alg but no secret', async () => {
      // RS256-signed token so the token-level alg check passes; the config-level
      // check must then catch the misconfigured HS256+no-secret combination.
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [
            { issuer: 'https://tenant1.example.com/', alg: 'HS256' }, // no secret
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Issuer specifies symmetric algorithm but no secret provided'
      );
    });

    it('should reject when dynamic resolver returns config with secret but asymmetric alg', async () => {
      const secret = randomBytes(32).toString('hex');
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret, // HS256-signed token
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [
            { issuer: 'https://tenant1.example.com/', alg: 'RS256', secret },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        'Issuer provides a secret but specifies asymmetric algorithm '
      );
    });

    it('should reject when dynamic resolver returns config with secret but no alg', async () => {
      const secret = randomBytes(32).toString('hex');
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret, // HS256-signed token
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [
            { issuer: 'https://tenant1.example.com/', secret } as any, // no alg
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Issuer provides a secret but no 'alg' specified"
      );
    });
  });    describe('URL normalization security warnings', () => {
      let consoleSpy: jest.SpyInstance;

      beforeEach(() => {
        consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      });

      afterEach(() => {
        consoleSpy.mockRestore();
      });

      it('should throw error for userinfo in issuer URL', () => {
        expect(() => {
          jwtVerifier({
            mcd: {
              issuers: ['https://user:pass@tenant1.example.com/'],
            },
            audience: 'https://api/',
          });
        }).toThrow('Invalid issuer URL: URLs must not contain userinfo (username:password)');
      });

      it('should throw error for query parameters in issuer URL', () => {
        expect(() => {
          jwtVerifier({
            mcd: {
              issuers: ['https://tenant1.example.com/?debug=true&env=test'],
            },
            audience: 'https://api/',
          });
        }).toThrow('Invalid issuer URL: URLs must not contain query parameters');
      });

      it('should throw error for URL fragments in issuer URL', () => {
        expect(() => {
          jwtVerifier({
            mcd: {
              issuers: ['https://tenant1.example.com/#section'],
            },
            audience: 'https://api/',
          });
        }).toThrow('Invalid issuer URL: URLs must not contain fragments');
      });

      it('should throw error for HTTP in production environment', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        try {
          expect(() => {
            jwtVerifier({
              mcd: {
                issuers: ['http://tenant1.example.com:8080/'],
              },
              audience: 'https://api/',
            });
          }).toThrow('HTTP issuer URL detected in production environment. Use HTTPS for security.');
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should not throw error for HTTP in non-production environments', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'development';

        try {
          const jwt = await createJwt({
            issuer: 'http://tenant1.example.com:8080/',
          });

          const verify = jwtVerifier({
            mcd: {
              issuers: ['http://tenant1.example.com:8080/'],
            },
            audience: 'https://api/',
          });

          // Should work fine in development
          await verify(jwt);
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should throw error for multiple security issues in same URL', () => {
        expect(() => {
          jwtVerifier({
            mcd: {
              issuers: ['https://user:pass@tenant1.example.com/?debug=true#section'],
            },
            audience: 'https://api/',
          });
        }).toThrow('Invalid issuer URL: URLs must not contain userinfo (username:password)');
      });
    });

  // ---------------------------------------------------------------------------
  // publicKey option (issue #133)
  // ---------------------------------------------------------------------------
  describe('publicKey option (static asymmetric key without discovery)', () => {
    // -- Configuration validation --------------------------------------------

    it('should throw when publicKey and jwksUri are both provided', () => {
      expect(() =>
        jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
          publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
          tokenSigningAlg: 'RS256',
        })
      ).toThrowError("You must not provide both a 'publicKey' and 'jwksUri'");
    });

    it('should throw when publicKey and secret are both provided', () => {
      expect(() =>
        jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          secret: 'some-secret',
          publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
          tokenSigningAlg: 'HS256',
        })
      ).toThrowError("You must not provide both a 'publicKey' and 'secret'");
    });

    it('should throw when publicKey and issuerBaseURL are both provided', () => {
      expect(() =>
        jwtVerifier({
          issuerBaseURL: 'https://issuer.example.com/',
          audience: 'https://api/',
          publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
          tokenSigningAlg: 'RS256',
        })
      ).toThrowError("You must not provide both a 'publicKey' and 'issuerBaseURL'");
    });

    it('should throw when top-level publicKey is combined with mcd', () => {
      expect(() =>
        jwtVerifier({
          mcd: { issuers: ['https://tenant1.example.com/'] },
          audience: 'https://api/',
          publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
        })
      ).toThrowError('Cannot use top-level "publicKey" with mcd mode.');
    });

    it('should throw when PEM publicKey is used without tokenSigningAlg', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey();
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyPem,
        // tokenSigningAlg intentionally omitted
      });
      await expect(verify(jwt)).rejects.toThrowError(
        "You must provide 'tokenSigningAlg' (or 'alg' in the issuer config) when using a PEM public key"
      );
    });

    // -- Successful verification with PEM ------------------------------------

    it('should verify token using PEM SPKI public key', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey();
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyPem,
        tokenSigningAlg: 'RS256',
      });
      await expect(verify(jwt)).resolves.toHaveProperty('payload', {
        iss: 'https://issuer.example.com/',
        sub: 'me',
        aud: 'https://api/',
        iat: expect.any(Number),
        exp: expect.any(Number),
      });
    });

    it('should reject a token signed with a different key when using PEM', async () => {
      const { jwt } = await createJwtWithKey();
      // Generate a completely different key for verification
      const { publicKeyPem: wrongPem } = await createJwtWithKey();
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: wrongPem,
        tokenSigningAlg: 'RS256',
      });
      await expect(verify(jwt)).rejects.toThrow(InvalidTokenError);
    });

    // -- Successful verification with JWK ------------------------------------

    it('should verify token using a single JWK public key', async () => {
      const { jwt, publicKeyJwk } = await createJwtWithKey();
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyJwk,
        tokenSigningAlg: 'RS256',
      });
      await expect(verify(jwt)).resolves.toHaveProperty('payload.iss', 'https://issuer.example.com/');
    });

    it('should verify token using a JWK with alg field (no tokenSigningAlg needed)', async () => {
      const { jwt, publicKeyJwk } = await createJwtWithKey();
      // publicKeyJwk already has alg: 'RS256' set by createJwtWithKey
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyJwk,
        // tokenSigningAlg intentionally omitted — alg comes from the JWK
      });
      await expect(verify(jwt)).resolves.toHaveProperty('payload.iss', 'https://issuer.example.com/');
    });

    // -- Successful verification with JWK Set --------------------------------

    it('should verify token using an inline JWK Set', async () => {
      const { jwt, publicKeyJwkSet } = await createJwtWithKey();
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyJwkSet,
      });
      await expect(verify(jwt)).resolves.toHaveProperty('payload.sub', 'me');
    });

    it('should reject a token when the kid does not match any key in the inline JWK Set', async () => {
      const { jwt } = await createJwtWithKey({ kid: 'key-1' });
      // JWK Set contains a key with a different kid
      const { publicKeyJwkSet } = await createJwtWithKey({ kid: 'key-2' });
      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        publicKey: publicKeyJwkSet,
      });
      await expect(verify(jwt)).rejects.toThrow(InvalidTokenError);
    });

    // -- No discovery / no network calls -------------------------------------

    it('should not make any network requests when publicKey is provided', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey();
      // nock.disableNetConnect would throw on any network call; the test passes
      // only if the verifier uses the static key without hitting the network.
      nock.disableNetConnect();
      try {
        const verify = jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          publicKey: publicKeyPem,
          tokenSigningAlg: 'RS256',
        });
        await expect(verify(jwt)).resolves.toHaveProperty('payload');
      } finally {
        nock.enableNetConnect();
      }
    });

    // -- MCD with publicKey --------------------------------------------------

    it('should verify token in MCD mode using per-issuer PEM publicKey', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey({
        issuer: 'https://tenant1.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant1.example.com/',
              publicKey: publicKeyPem,
              alg: 'RS256',
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload.iss', 'https://tenant1.example.com/');
    });

    it('should verify token in MCD mode using per-issuer JWK publicKey', async () => {
      const { jwt, publicKeyJwk } = await createJwtWithKey({
        issuer: 'https://tenant2.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant2.example.com/',
              publicKey: publicKeyJwk,
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload.iss', 'https://tenant2.example.com/');
    });

    it('should verify token in MCD mode using per-issuer JWK Set publicKey', async () => {
      const { jwt, publicKeyJwkSet } = await createJwtWithKey({
        issuer: 'https://tenant3.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://tenant3.example.com/',
              publicKey: publicKeyJwkSet,
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload.iss', 'https://tenant3.example.com/');
    });

    it('should support mixed MCD issuers: one with publicKey, one with JWKS discovery', async () => {
      const { jwt: jwtStatic, publicKeyPem } = await createJwtWithKey({
        issuer: 'https://static.example.com/',
      });
      const jwtDiscovery = await createJwt({
        issuer: 'https://discovery.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: [
            {
              issuer: 'https://static.example.com/',
              publicKey: publicKeyPem,
              alg: 'RS256',
            },
            'https://discovery.example.com/',
          ] as any,
        },
        audience: 'https://api/',
      });

      await expect(verify(jwtStatic)).resolves.toHaveProperty('payload.iss', 'https://static.example.com/');
      await expect(verify(jwtDiscovery)).resolves.toHaveProperty('payload.iss', 'https://discovery.example.com/');
    });

    it('should throw in MCD static config when issuer has both publicKey and jwksUri', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.example.com/',
                publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
                jwksUri: 'https://tenant1.example.com/.well-known/jwks.json',
              },
            ],
          },
          audience: 'https://api/',
        })
      ).toThrowError(
        "provides both 'publicKey' and 'jwksUri'. These are mutually exclusive."
      );
    });

    it('should throw in MCD static config when issuer has both publicKey and secret', () => {
      expect(() =>
        jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant1.example.com/',
                publicKey: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----',
                secret: 'my-secret',
                alg: 'HS256',
              } as any,
            ],
          },
          audience: 'https://api/',
        })
      ).toThrowError(
        "provides both 'publicKey' and 'secret'."
      );
    });

    it('should throw at runtime when dynamic resolver returns issuer with both publicKey and secret', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey({
        issuer: 'https://tenant-dynamic.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [
            {
              issuer: 'https://tenant-dynamic.example.com/',
              publicKey: publicKeyPem,
              secret: 'my-secret',
              alg: 'HS256',
            } as any,
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Issuer provides both 'publicKey' and 'secret'. These are mutually exclusive."
      );
    });

    it('should throw at runtime when dynamic resolver returns issuer with both publicKey and jwksUri', async () => {
      const { jwt, publicKeyPem } = await createJwtWithKey({
        issuer: 'https://tenant-dynamic2.example.com/',
      });

      const verify = jwtVerifier({
        mcd: {
          issuers: async () => [
            {
              issuer: 'https://tenant-dynamic2.example.com/',
              publicKey: publicKeyPem,
              jwksUri: 'https://tenant-dynamic2.example.com/.well-known/jwks.json',
            },
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Issuer provides both 'publicKey' and 'jwksUri'. These are mutually exclusive."
      );
    });

    it('should make no network requests for MCD with publicKey (no discovery)', async () => {
      const { jwt, publicKeyJwkSet } = await createJwtWithKey({
        issuer: 'https://tenant-static.example.com/',
      });

      nock.disableNetConnect();
      try {
        const verify = jwtVerifier({
          mcd: {
            issuers: [
              {
                issuer: 'https://tenant-static.example.com/',
                publicKey: publicKeyJwkSet,
              },
            ],
          },
          audience: 'https://api/',
        });

        await expect(verify(jwt)).resolves.toHaveProperty('payload');
      } finally {
        nock.enableNetConnect();
      }
    });
  });
});
