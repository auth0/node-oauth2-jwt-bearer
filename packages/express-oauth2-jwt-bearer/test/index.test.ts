import { AddressInfo } from 'net';
import { Server } from 'http';
import { randomBytes } from 'crypto';
import { Handler } from 'express';
import express from 'express';
import nock from 'nock';
import got, { CancelableRequest } from 'got';
import { createJwt } from 'access-token-jwt/test/helpers';
import {
  auth,
  AuthOptions,
  claimCheck,
  claimEquals,
  claimIncludes,
  requiredScopes,
  scopeIncludesAny,
  UnauthorizedError,
  InvalidRequestError,
  InvalidTokenError,
  InsufficientScopeError,
} from '../src';

const expectFailsWith = async (
  promise: CancelableRequest,
  status: number,
  code?: string,
  description?: string,
  scopes?: string
) => {
  try {
    await promise;
    fail('Request should fail');
  } catch (e) {
    const error = code ? `, error="${code}"` : '';
    const errorDescription = description
      ? `, error_description="${description}"`
      : '';
    expect(e.response.statusCode).toBe(status);
    const expectedChallenge = `Bearer realm="api"${error}${errorDescription}${(scopes && ', scope="' + scopes + '"') || ''}`;
    expect(e.response.headers['www-authenticate']).toContain(expectedChallenge);
  }
};

describe('index', () => {
  let server: Server;

  afterEach((done) => {
    nock.cleanAll();
    (server?.listening && server.close(done)) || done();
  });

  const setup = (
    opts: AuthOptions & {
      middleware?: Handler;
    } = {}
  ) => {
    const app = express();
    const { middleware, ...authOpts } = opts;
    app.use(express.urlencoded({ extended: false }));

    app.use(
      auth({
        issuerBaseURL: 'https://issuer.example.com/',
        audience: 'https://api/',
        ...authOpts,
      })
    );

    if (middleware) {
      app.use(middleware);
    }

    app.all('/', (req, res, next) => {
      try {
        res.json(req.auth);
        next();
      } catch (e) {
        next(e);
      }
    });

    return new Promise<string>((resolve) => {
      server = app.listen(0, () =>
        resolve(`http://localhost:${(server.address() as AddressInfo).port}`)
      );
    });
  };

  it('should fail for anonymous requests', async () => {
    const baseUrl = await setup();
    await expectFailsWith(got(baseUrl), 401);
  });

  it('should succeed for anonymous requests when authRequired is false', async () => {
    const baseUrl = await setup({ authRequired: false });
    const response = await got(baseUrl, {
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBeFalsy();
  });

  it('should succeed for invalid requests when authRequired is false', async () => {
    const baseUrl = await setup({ authRequired: false });
    const response = await got(baseUrl, {
      headers: { authorization: 'Bearer invalid.jwt' },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBeFalsy();
  });

  it('should fail for anonymous requests when authRequired is true', async () => {
    const baseUrl = await setup({ authRequired: true });
    await expectFailsWith(got(baseUrl), 401);
  });

  it('should accept empty arguments and env vars', async () => {
    const env = process.env;
    await expect(auth).toThrowError(
      "You must provide 'mcd', 'issuerBaseURL', or both 'issuer' and ('jwksUri', 'secret', or 'publicKey')"
    );
    process.env = Object.assign({}, env, {
      ISSUER_BASE_URL: 'foo',
    });
    expect(auth).toThrow(
      "An 'audience' is required to validate the 'aud' claim"
    );
    process.env = Object.assign({}, env, {
      ISSUER_BASE_URL: 'foo',
      AUDIENCE: 'baz',
    });
    expect(auth).not.toThrow();
    process.env = Object.assign({}, env, {
      ISSUER: 'bar',
      JWKS_URI: 'qux',
      AUDIENCE: 'baz',
    });
    expect(auth).not.toThrow();
    process.env = Object.assign({}, env, {
      ISSUER: 'bar',
      SECRET: randomBytes(32).toString('hex'),
      TOKEN_SIGNING_ALG: 'HS256',
      AUDIENCE: 'baz',
    });
    expect(auth).not.toThrow();
    process.env = env;
  });

  it('should succeed for authenticated requests', async () => {
    const jwt = await createJwt();
    const baseUrl = await setup();
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        iss: 'https://issuer.example.com/',
      })
    );
  });

  it('should succeed for authenticated requests signed with symmetric keys', async () => {
    const secret = randomBytes(32).toString('hex');
    const jwt = await createJwt({ secret });
    const baseUrl = await setup({
      secret,
      tokenSigningAlg: 'HS256',
    });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        iss: 'https://issuer.example.com/',
      })
    );
  });

  it('should fail for requests signed with invalid symmetric keys', async () => {
    const jwt = await createJwt({ secret: randomBytes(32).toString('hex') });
    const baseUrl = await setup({
      secret: randomBytes(32).toString('hex'),
      tokenSigningAlg: 'HS256',
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      'signature verification failed'
    );
  });

  it('should fail for audience mismatch', async () => {
    const jwt = await createJwt({ audience: 'bar' });
    const baseUrl = await setup({
      audience: 'foo',
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      `Unexpected 'aud' value`
    );
  });

  it('should fail when custom validator fails', async () => {
    const jwt = await createJwt();
    const baseUrl = await setup({
      validators: {
        foo: () => false,
      },
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      `Unexpected 'foo' value`
    );
  });

  it('should succeed for POST requests with custom character encoding', async () => {
    const jwt = await createJwt();
    const baseUrl = await setup();
    const response = await got(baseUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
      },
      form: { access_token: jwt },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
  });

  it('should fail with custom claim check for anonymous request', async () => {
    const app = express();
    app.use(claimCheck(() => false));
    const baseUrl = await new Promise<string>((resolve) => {
      server = app.listen(0, () =>
        resolve(`http://localhost:${(server.address() as AddressInfo).port}`)
      );
    });
    try {
      await got(baseUrl);
    } catch ({ response }) {
      expect(response.statusCode).toBe(401);
      expect(response.headers).toMatchObject({
        'www-authenticate': 'Bearer realm="api"',
      });
    }
  });

  it('should fail when custom claim check returns false', async () => {
    const jwt = await createJwt({ payload: { num: 2 } });
    const baseUrl = await setup({
      middleware: claimCheck(
        ({ num }) => typeof num === 'number' && num > 3,
        "'num' too small"
      ),
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      "'num' too small"
    );
  });

  it('should succeed when custom claim check returns true', async () => {
    const jwt = await createJwt({ payload: { num: 4 } });
    const baseUrl = await setup({
      middleware: claimCheck(
        ({ num }) => typeof num === 'number' && num > 3,
        '"num" too small'
      ),
    });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        num: 4,
      })
    );
  });

  it('should fail when actual claim does not equal expected claim', async () => {
    const jwt = await createJwt({ payload: { foo: 'baz' } });
    const baseUrl = await setup({ middleware: claimEquals('foo', 'bar') });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      "Unexpected 'foo' value"
    );
  });

  it('should succeed when actual claim does equals expected claim', async () => {
    const jwt = await createJwt({ payload: { foo: 'bar' } });
    const baseUrl = await setup({ middleware: claimEquals('foo', 'bar') });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        foo: 'bar',
      })
    );
  });

  it('should fail when actual claim does not include expected claims', async () => {
    const jwt = await createJwt({ payload: { foo: 'bar qux' } });
    const baseUrl = await setup({
      middleware: claimIncludes('foo', 'bar', 'baz'),
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      "Unexpected 'foo' value"
    );
  });

  it('should succeed when actual claim includes expected claims', async () => {
    const jwt = await createJwt({ payload: { foo: ['bar', 'baz'] } });
    const baseUrl = await setup({
      middleware: claimIncludes('foo', 'bar', 'baz'),
    });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        foo: ['bar', 'baz'],
      })
    );
  });

  it('should fail when required scopes are not included', async () => {
    const jwt = await createJwt({ payload: { scope: 'foo bar' } });
    const baseUrl = await setup({
      middleware: requiredScopes(['foo', 'bar', 'baz']),
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      403,
      'insufficient_scope',
      'Insufficient Scope',
      'foo bar baz'
    );
  });

  it('should succeed when required scopes are included', async () => {
    const jwt = await createJwt({ payload: { scope: ['foo', 'bar', 'baz'] } });
    const baseUrl = await setup({
      middleware: requiredScopes('foo bar'),
    });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        scope: ['foo', 'bar', 'baz'],
      })
    );
  });

  it('should replace double quotes in header with single quotes', async () => {
    const jwt = await createJwt({ payload: { nbf: false } });
    const baseUrl = await setup();
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      401,
      'invalid_token',
      "'nbf' claim must be a number"
    );
  });

  it('should export errors', () => {
    expect(() => {
      throw new UnauthorizedError();
    }).toThrow(UnauthorizedError);
    expect(() => {
      throw new InvalidRequestError();
    }).toThrow(InvalidRequestError);
    expect(() => {
      throw new InvalidTokenError();
    }).toThrow(InvalidTokenError);
    expect(() => {
      throw new InsufficientScopeError();
    }).toThrow(InsufficientScopeError);
  });

  it('should fail when required scopes are not included', async () => {
    const jwt = await createJwt({ payload: { scope: 'qux quxx' } });
    const baseUrl = await setup({
      middleware: scopeIncludesAny(['foo', 'bar', 'baz']),
    });
    await expectFailsWith(
      got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
        },
        responseType: 'json',
      }),
      403,
      'insufficient_scope',
      'Insufficient Scope',
      'foo bar baz'
    );
  });

  it('should succeed when required scopes are included', async () => {
    const jwt = await createJwt({ payload: { scope: ['foo', 'bar', 'baz'] } });
    const baseUrl = await setup({
      middleware: scopeIncludesAny('foo bar'),
    });
    const response = await got(baseUrl, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toHaveProperty(
      'payload',
      expect.objectContaining({
        scope: ['foo', 'bar', 'baz'],
      })
    );
  });

  it('for full coverage: should use req.url when req.originalUrl is undefined', async () => {
    const jwt = await createJwt();
    const app = express();
  
    // Simulate a broken originalUrl (force it to be undefined)
    app.use((req, res, next) => {
      // @ts-ignore
      delete req.originalUrl;
      next();
    });
  
    app.use(
      auth({
        issuerBaseURL: 'https://issuer.example.com/',
        audience: 'https://api/',
      })
    );
  
    app.get('/test-url', (req, res) => {
      res.json({ success: true });
    });
  
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
  
    const address = server.address() as AddressInfo;
    const url = `http://localhost:${address.port}/test-url`;
  
    const response = await got(url, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });
  
    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({ success: true });
  
    server.close();
  });
  

  describe('Host injection rejection (DPoP htu bypass fix)', () => {
    // FT-1: attack ? variant rejected
    test('FT-1: rejects GET with Host carrying injected path+query (?)', async () => {
      const baseUrl = await setup({
        dpop: { enabled: true, required: true },
      });
      await expectFailsWith(
        got(baseUrl, {
          headers: { host: 'localhost/intendedPath?' },
          responseType: 'json',
        }),
        400,
        'invalid_request'
      );
    });

    // FT-2: attack # variant rejected
    test('FT-2: rejects GET with Host carrying injected path+fragment (#)', async () => {
      const baseUrl = await setup({
        dpop: { enabled: true, required: true },
      });
      await expectFailsWith(
        got(baseUrl, {
          headers: { host: 'localhost/intendedPath#' },
          responseType: 'json',
        }),
        400,
        'invalid_request'
      );
    });

    // FT-6: invalid host with authRequired:false proceeds
    test('FT-6: invalid host with authRequired:false passes through', async () => {
      const baseUrl = await setup({
        authRequired: false,
        dpop: { enabled: true },
      });
      const response = await got(baseUrl, {
        headers: { host: 'resource.com/evil?' },
        responseType: 'json',
      });
      // Should reach the downstream handler without throwing
      expect(response.statusCode).toBe(200);
      expect(response.body).toBeFalsy(); // No auth, so req.auth is undefined
    });

  });

  describe('mTLS (RFC 8705) certificate-bound tokens', () => {
    const { execFileSync } = require('child_process');
    const { createHash } = require('crypto');
    const { tmpdir } = require('os');
    const { join } = require('path');
    const fs = require('fs');

    let certPem: string;
    let certThumbprint: string;

    beforeAll(() => {
      const dir = join(tmpdir(), `mtls-express-${process.pid}`);
      fs.mkdirSync(dir, { recursive: true });
      try {
        const key = join(dir, 'client.key');
        const crt = join(dir, 'client.crt');
        execFileSync('openssl', [
          'req', '-x509', '-newkey', 'rsa:2048',
          '-keyout', key, '-out', crt,
          '-days', '1', '-nodes', '-subj', '/CN=client',
        ]);
        certPem = fs.readFileSync(crt, 'utf8');
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
      const PEM_RE =
        /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/;
      const der = Buffer.from(
        certPem.match(PEM_RE)![1].replace(/\s+/g, ''),
        'base64'
      );
      certThumbprint = createHash('sha256')
        .update(der)
        .digest('base64url');
    });

    it('passes through a cert-bound token unvalidated when getCertificate is not configured (mTLS is opt-in)', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({});
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
    });

    it('does not validate mTLS when explicitly disabled, even with getCertificate configured', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': 'not-the-real-thumbprint' } },
      });
      const baseUrl = await setup({
        mtls: { enabled: false },
        getCertificate: () => certPem,
      });
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
    });

    it('accepts a cert-bound token when the presented certificate matches', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({
        getCertificate: () => certPem,
      });
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
      expect((response.body as any).payload.cnf['x5t#S256']).toBe(
        certThumbprint
      );
    });

    it('rejects a cert-bound token when the certificate does not match', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': 'not-the-real-thumbprint' } },
      });
      const baseUrl = await setup({
        getCertificate: () => certPem,
      });
      await expectFailsWith(
        got(baseUrl, {
          headers: { authorization: `Bearer ${jwt}` },
          responseType: 'json',
        }),
        401,
        'invalid_token'
      );
    });

    it('rejects a cert-bound token when no certificate is presented', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({
        getCertificate: () => undefined,
      });
      // A cert-bound token received without a presented certificate is a
      // malformed request (InvalidRequestError -> 400 invalid_request), not an
      // invalid token.
      await expectFailsWith(
        got(baseUrl, {
          headers: { authorization: `Bearer ${jwt}` },
          responseType: 'json',
        }),
        400,
        'invalid_request'
      );
    });

    it('accepts a plain bearer token unaffected when mTLS is not triggered', async () => {
      const jwt = await createJwt({ payload: { foo: 'bar' } });
      const baseUrl = await setup({
        getCertificate: () => certPem,
      });
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
      expect((response.body as any).payload.foo).toBe('bar');
    });

    it('rejects a plain bearer token when mTLS is required', async () => {
      const jwt = await createJwt({ payload: { foo: 'bar' } });
      const baseUrl = await setup({
        mtls: { required: true },
        getCertificate: () => certPem,
      });
      await expectFailsWith(
        got(baseUrl, {
          headers: { authorization: `Bearer ${jwt}` },
          responseType: 'json',
        }),
        401,
        'invalid_token'
      );
    });

    it('resolves the certificate from a proxy header via getCertificate', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({
        getCertificate: (req) => {
          const header = req.headers['client-certificate'];
          return typeof header === 'string'
            ? decodeURIComponent(header)
            : undefined;
        },
      });
      const response = await got(baseUrl, {
        headers: {
          authorization: `Bearer ${jwt}`,
          'client-certificate': encodeURIComponent(certPem),
        },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
    });

    it('does not skip JWT verification for a plain bearer token when getCertificate throws', async () => {
      // getCertificate failing must not short-circuit verification for tokens
      // that never needed a certificate in the first place.
      const jwt = await createJwt({ payload: { foo: 'bar' } });
      const baseUrl = await setup({
        getCertificate: () => {
          throw new InvalidRequestError('bad proxy header');
        },
      });
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
      expect((response.body as any).payload.foo).toBe('bar');
    });

    it('rejects a cert-bound token for a missing certificate when getCertificate throws', async () => {
      // The resolver's own error is not propagated: the certificate is simply
      // treated as unresolved, and the cert-bound token is rejected the same
      // way it would be with no getCertificate configured at all.
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({
        getCertificate: () => {
          throw new InvalidRequestError('bad proxy header');
        },
      });
      await expectFailsWith(
        got(baseUrl, {
          headers: { authorization: `Bearer ${jwt}` },
        }),
        400,
        'invalid_request',
        'A client certificate is required for this certificate-bound access token'
      );
    });

    it('ignores an error thrown by getCertificate when authRequired is false', async () => {
      const jwt = await createJwt({
        payload: { cnf: { 'x5t#S256': certThumbprint } },
      });
      const baseUrl = await setup({
        authRequired: false,
        getCertificate: () => {
          throw new Error('boom');
        },
      });
      const response = await got(baseUrl, {
        headers: { authorization: `Bearer ${jwt}` },
        responseType: 'json',
      });
      expect(response.statusCode).toBe(200);
      expect(response.body).toBeFalsy();
    });
  });

});
