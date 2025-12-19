import { randomBytes, generateKeyPairSync } from 'crypto';
import nock from 'nock';
import sinon from 'sinon';
import { SignJWT } from 'jose';
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
      "You must provide an 'issuerBaseURL', an 'issuer' and 'jwksUri' or an 'issuer' and 'secret'"
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

  describe('with public key support (KeyLike)', () => {
    it('should accept KeyLike public key without tokenSigningAlg', () => {
      const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

      expect(() =>
        jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          secret: publicKey,
        })
      ).not.toThrow();
    });

    it('should accept KeyLike public key with asymmetric tokenSigningAlg', () => {
      const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

      expect(() =>
        jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          secret: publicKey,
          tokenSigningAlg: 'RS256',
        })
      ).not.toThrow();
    });

    it('should verify JWT signed with matching private key', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      const jwt = await new SignJWT({ sub: 'user123', extra: 'data' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
      });

      const result = await verify(jwt);
      expect(result.payload.sub).toBe('user123');
      expect(result.payload.extra).toBe('data');
    });

    it('should reject JWT signed with different private key', async () => {
      const { privateKey: privateKey1 } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const { publicKey: publicKey2 } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      const jwt = await new SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey1);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey2,
      });

      await expect(verify(jwt)).rejects.toThrow();
    });

    it('should work with EC keys (ES256)', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });

      const jwt = await new SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
        tokenSigningAlg: 'ES256',
      });

      const result = await verify(jwt);
      expect(result.payload.sub).toBe('user123');
    });

    it('should work with EdDSA keys', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');

      const jwt = await new SignJWT({ sub: 'user456' })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
        tokenSigningAlg: 'EdDSA',
      });

      const result = await verify(jwt);
      expect(result.payload.sub).toBe('user456');
    });

    it('should reject expired JWT even with valid signature', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      const jwt = await new SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://api/')
        .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
      });

      await expect(verify(jwt)).rejects.toThrow();
    });

    it('should reject JWT with wrong issuer', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      const jwt = await new SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('https://wrong-issuer.com/')
        .setAudience('https://api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
      });

      await expect(verify(jwt)).rejects.toThrowError("Unexpected 'iss' value");
    });

    it('should reject JWT with wrong audience', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      const jwt = await new SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('https://issuer.example.com/')
        .setAudience('https://different-api/')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const verify = jwtVerifier({
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
        secret: publicKey,
      });

      await expect(verify(jwt)).rejects.toThrowError("Unexpected 'aud' value");
    });

    it('should still require tokenSigningAlg for string secrets', () => {
      expect(() =>
        jwtVerifier({
          issuer: 'https://issuer.example.com/',
          audience: 'https://api/',
          secret: 'my-secret-string',
        })
      ).toThrowError(
        "You must provide a 'tokenSigningAlg' for validating symmetric algorithms"
      );
    });
  });
});
