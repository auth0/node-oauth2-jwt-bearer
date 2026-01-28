import { randomBytes } from 'crypto';
import nock from 'nock';
import sinon from 'sinon';
import { createJwt, now } from './helpers';
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
      "You must provide 'auth0MCD', 'issuerBaseURL', or both 'issuer' and ('jwksUri' or 'secret')"
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

  // MCD Tests
  describe('MCD (Multiple Custom Domains)', () => {
    it('should throw when both auth0MCD and issuerBaseURL are provided', () => {
      expect(() =>
        jwtVerifier({
          auth0MCD: {
            issuers: ['https://tenant1.auth0.com'],
          },
          issuerBaseURL: 'https://tenant1.auth0.com',
          audience: 'https://api/',
        })
      ).toThrowError(
        "You must not provide both 'auth0MCD' and 'issuerBaseURL'"
      );
    });

    it('should throw when auth0MCD is provided without issuers', () => {
      expect(() =>
        jwtVerifier({
          auth0MCD: {} as any,
          audience: 'https://api/',
        })
      ).toThrowError("Invalid MCD configuration: 'issuers' is required");
    });

    it('should verify token with MCD static issuer (string)', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
          issuers: [
            'https://tenant1.example.com/',
            'https://tenant2.example.com/',
          ],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Issuer 'https://unauthorized.example.com/' is not allowed"
      );
    });

    it('should throw when token missing iss claim in MCD mode', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        payload: {},
      });
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
          issuers: async (context) => {
            // Dynamic resolver that returns allowed issuers
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
        auth0MCD: {
          issuers: async (context) => {
            return 'https://tenant1.example.com/';
          },
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');
    });

    it('should work with MCD dynamic resolver returning config objects', async () => {
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        jwksUri: '/.well-known/jwks.json',
        discoveryUri: '/.well-known/openid-configuration',
      });

      const verify = jwtVerifier({
        auth0MCD: {
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
        auth0MCD: {
          issuers: resolverSpy,
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).resolves.toHaveProperty('payload');

      expect(resolverSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenClaims: expect.objectContaining({
            iss: 'https://tenant1.example.com/',
            org_id: 'org123',
          }),
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        auth0MCD: {
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
        "Issuer 'https://tenant1.example.com/' is not allowed"
      );
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
        auth0MCD: {
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
        auth0MCD: {
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
        'No JWKS URI or secret available for verification'
      );
    });

    it('should reject symmetric algorithm (HS256) without secret configured', async () => {
      const secret = randomBytes(32).toString('hex');
      const jwt = await createJwt({
        issuer: 'https://tenant1.example.com/',
        secret, // Token is signed with HS256
      });

      const verify = jwtVerifier({
        auth0MCD: {
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
        'Symmetric algorithms (HS256, HS384, HS512) are not supported for JWKS-based verification'
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
        auth0MCD: {
          issuers: ['https://tenant1.example.com/'],
        },
        audience: 'https://api/',
      });

      await expect(verify(jwt)).rejects.toThrowError(
        "Discovery metadata issuer 'https://different-tenant.example.com/' does not match token issuer 'https://tenant1.example.com/'"
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
        auth0MCD: {
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
          tokenClaims: expect.objectContaining({
            iss: 'https://tenant1.example.com/',
          }),
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
        auth0MCD: {
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
          tokenClaims: expect.objectContaining({
            iss: 'https://tenant1.example.com/',
          }),
        })
      );
    });
  });
});
