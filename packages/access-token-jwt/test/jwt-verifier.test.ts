import nock = require('nock');
import { createJwt, now } from './helpers';
import { jwtVerifier, InvalidTokenError } from '../src';

describe('jwt-verifier', () => {
  afterEach(nock.cleanAll);

  it('should throw when configured with no issuer', async () => {
    expect(() =>
      jwtVerifier({
        jwksUri: '',
        issuer: 'https://issuer.example.com/',
        audience: 'https://api/',
      })
    ).toThrowError(
      'You must provide an "issuerBaseURL" or an "issuer" and "jwksUri"'
    );
  });

  it('should throw when configured with no audience', async () => {
    expect(() =>
      jwtVerifier({
        jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
        issuer: 'https://issuer.example.com/',
        audience: '',
      })
    ).toThrowError('An "audience" is required to validate the "aud" claim');
  });

  it('should verify the token', async () => {
    const jwt = await createJwt();

    const verify = jwtVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toMatchObject({
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
    await expect(verify(jwt)).rejects.toThrowError(
      'unexpected "iss" claim value'
    );
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
    await expect(verify(jwt)).rejects.toThrowError(
      'unexpected "aud" claim value'
    );
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

  it('should use discovered issuer over issuer base url', async () => {
    const jwt = await createJwt({
      issuer: 'https://issuer.example.com',
    });

    const verify = jwtVerifier({
      issuerBaseURL:
        'https://issuer.example.com/.well-known/openid-configuration',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toBeTruthy();
  });

  it('should fail with invalid_token error', async () => {
    const jwt = await createJwt({
      issuer: 'https://issuer.example.com',
    });
    const verify = jwtVerifier({
      issuerBaseURL:
        'https://issuer.example.com/.well-known/openid-configuration',
      issuer: 'https://wrong.example.com',
      audience: 'https://api/',
    });
    await expect(verify(`CORRUPT-${jwt}`)).rejects.toThrow(InvalidTokenError);
  });

  it('should use configured issuer over discovered issuer', async () => {
    const jwt = await createJwt({
      issuer: 'https://issuer.example.com',
    });

    const verify = jwtVerifier({
      issuerBaseURL:
        'https://issuer.example.com/.well-known/openid-configuration',
      issuer: 'https://wrong.example.com',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).rejects.toThrowError(
      'unexpected "iss" claim value'
    );
  });
});
