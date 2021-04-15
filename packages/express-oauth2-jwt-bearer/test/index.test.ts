import { AddressInfo } from 'net';
import { Server } from 'http';
import express = require('express');
import nock = require('nock');
import got, { CancelableRequest } from 'got';
import { createJwt } from 'access-token-jwt/test/helpers';
import { auth } from '../src';

const expectFailsWith = async (
  promise: CancelableRequest,
  status: number,
  code: string,
  description: string
) => {
  try {
    await promise;
    fail('Request should fail');
  } catch (e) {
    expect(e.response.statusCode).toBe(status);
    expect(e.response.headers['www-authentication']).toBe(
      `Bearer realm="api", error="${code}", error_description="${description}"`
    );
  }
};

describe('index', () => {
  let server: Server;

  afterEach((done) => {
    nock.cleanAll();
    server && server.close(done);
  });

  const setup = (opts?: any) => {
    const app = express();

    app.use(
      auth({
        issuerBaseURL: 'https://issuer.example.com/',
        audience: 'https://api/',
        ...opts,
      })
    );

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
    expect(response.body).toMatchObject({
      iss: 'https://issuer.example.com/',
    });
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
      'unexpected "aud" claim value'
    );
  });
});
