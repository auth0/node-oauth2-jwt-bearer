import { AddressInfo } from 'net';
import { Server } from 'http';
import { Handler } from 'express';
import express = require('express');
import nock = require('nock');
import got, { CancelableRequest } from 'got';
import { WithDiscovery, WithoutDiscovery } from 'access-token-jwt';
import { createJwt } from 'access-token-jwt/test/helpers';
import {
  auth,
  claimCheck,
  claimEquals,
  claimIncludes,
  requiredScopes,
} from '../src';

const expectFailsWith = async (
  promise: CancelableRequest,
  status: number,
  code: string,
  description: string,
  scopes?: string
) => {
  try {
    await promise;
    fail('Request should fail');
  } catch (e) {
    expect(e.response.statusCode).toBe(status);
    expect(e.response.headers['www-authenticate']).toBe(
      `Bearer realm="api", error="${code}", error_description="${description}"${
        (scopes && ', scope="' + scopes + '"') || ''
      }`
    );
  }
};

describe('index', () => {
  let server: Server;

  afterEach((done) => {
    nock.cleanAll();
    server && server.close(done);
  });

  const setup = (
    opts: Partial<WithDiscovery | WithoutDiscovery> & {
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
    await expectFailsWith(
      got(baseUrl),
      400,
      'invalid_request',
      'Bearer token is missing'
    );
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
      'unexpected "aud" value'
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
      'unexpected "foo" value'
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
        '"num" too small'
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
      '"num" too small'
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
      '"foo" claim mismatch'
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
      '"foo" claim mismatch'
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
});
