import { Server } from 'http';
import { AddressInfo } from 'net';
import express from 'express';
import nock from 'nock';
import got from 'got';
import { createJwt } from 'access-token-jwt/test/helpers';
import { auth } from '../src';

describe('Integration: Token Exchange API', () => {
  let server: Server;

  afterEach((done) => {
    nock.cleanAll();
    (server?.listening && server.close(done)) || done();
  });

  it('should provide req.auth.exchange() method following express-openid-connect pattern', async () => {
    const jwt = await createJwt();
    const app = express();

    // Setup auth middleware
    app.use(auth({ 
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/'
    }));

    // Mock token exchange endpoint
    const mockTokenResponse = {
      access_token: 'exchanged-token',
      token_type: 'Bearer',
      expires_in: 3600,
    };

    nock('https://auth.example.com')
      .post('/oauth/token')
      .reply(200, mockTokenResponse);

    // Route that uses the new exchange API
    app.get('/exchange', async (req, res) => {
      try {
        // This is the new simplified API - one method on auth context
        const result = await req.auth!.exchange({
          tokenEndpoint: 'https://auth.example.com/oauth/token',
          clientId: 'test-client',
          targetAudience: 'https://target-api.example.com',
        });

        res.json({ 
          success: true, 
          exchangedToken: result.access_token,
          hasExchangeMethod: typeof req.auth?.exchange === 'function'
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Start server
    server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });

    const address = server.address() as AddressInfo;
    const url = `http://localhost:${address.port}/exchange`;

    // Make authenticated request
    const response = await got(url, {
      headers: { authorization: `Bearer ${jwt}` },
      responseType: 'json',
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({
      success: true,
      exchangedToken: 'exchanged-token',
      hasExchangeMethod: true,
    });
  });
});
