import { createServer, IncomingMessage, Server, ServerResponse } from 'http';
import { URL } from 'url';
import { AddressInfo } from 'net';
import anyBody = require('body/any');
import got from 'got';
import typeis = require('type-is');
import { getToken } from '../src';

const start = (server: Server): Promise<string> =>
  new Promise((resolve) =>
    server.listen(0, () =>
      resolve(`http://localhost:${(server.address() as AddressInfo).port}`)
    )
  );

const handler = (req: IncomingMessage, res: ServerResponse) => {
  let query: Record<string, string>;
  new URL(req.url as string, 'http://localhost').searchParams.forEach(
    (val, key) => {
      query = query || {};
      query[key] = val;
    }
  );
  anyBody(req, res, (err, body) => {
    try {
      // Extract options from query params for testing
      const options = {
        checkHeader: query?.checkHeader !== 'false',
        checkQuery: query?.checkQuery !== 'false',
        checkBody: query?.checkBody !== 'false'
      };
      
      // Remove the configuration params
      if (query) {
        delete query.checkHeader;
        delete query.checkQuery;
        delete query.checkBody;
      }
      
      res.end(
        getToken(
          req.headers,
          query,
          body as Record<string, string>,
          !!typeis.is(req.headers['content-type'] as string, ['urlencoded']),
          options
        )
      );
    } catch (e) {
      res.statusCode = e.statusCode;
      res.statusMessage = e.message;
      res.end();
    }
  });
};

describe('get-token', () => {
  let server: Server;
  let url: string;

  beforeEach(async () => {
    server = createServer(handler);
    url = await start(server);
  });

  afterEach((done) => {
    server.close(done);
  });

  it('should fail when there are no tokens', async () => {
    await expect(got(url)).rejects.toThrowError(
      'Response code 401 (Unauthorized)'
    );
  });

  it('should get the token from the header', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        headers: {
          authorization: 'Bearer token',
        },
      })
    ).resolves.toEqual('token');
  });

  it('should do case insensitive check for header', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        headers: {
          authorization: 'bearer token',
        },
      })
    ).resolves.toEqual('token');
  });

  it('should fail for malformed header', async () => {
    await expect(
      got(url, {
        headers: {
          authorization: 'foo token',
        },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should fail for empty header', async () => {
    await expect(
      got(url, {
        headers: {
          authorization: 'Bearer ',
        },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should get the token from the query string', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        searchParams: { access_token: 'token' },
      })
    ).resolves.toEqual('token');
  });

  it('should succeed to get the token from the query string for POST requests', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        method: 'POST',
        searchParams: { access_token: 'token' },
      })
    ).resolves.toEqual('token');
  });

  it('should get the token from the request payload', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        method: 'POST',
        form: { access_token: 'token' },
      })
    ).resolves.toEqual('token');
  });

  it('should fail to get the token from JSON request payload', async () => {
    await expect(
      got(url, {
        method: 'POST',
        json: { access_token: 'token' },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should succeed to get the token from request payload for GETs', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        allowGetBody: true,
        method: 'GET',
        form: { access_token: 'token' },
      })
    ).resolves.toEqual('token');
  });

  it('should fail if more than one method is used', async () => {
    await expect(
      got(url, {
        searchParams: { access_token: 'token' },
        headers: {
          authorization: 'Bearer token',
        },
      })
    ).rejects.toThrowError(
      'Response code 400 (More than one method used for authentication)'
    );
  });

  // New tests for token location options
  it('should not get token from header when disabled', async () => {
    await expect(
      got(url, {
        searchParams: { checkHeader: 'false' },
        headers: {
          authorization: 'Bearer token',
        },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should not get token from query when disabled', async () => {
    await expect(
      got(url, {
        searchParams: { 
          access_token: 'token',
          checkQuery: 'false'
        },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should not get token from body when disabled', async () => {
    await expect(
      got(url, {
        resolveBodyOnly: true,
        method: 'POST',
        searchParams: { checkBody: 'false' },
        form: { access_token: 'token' },
      })
    ).rejects.toThrowError('Response code 401 (Unauthorized)');
  });

  it('should allow configuring multiple token locations', async () => {
    // Disable both query and body, keep header
    await expect(
      got(url, {
        resolveBodyOnly: true,
        searchParams: { 
          checkQuery: 'false',
          checkBody: 'false'
        },
        headers: {
          authorization: 'Bearer token',
        },
      })
    ).resolves.toEqual('token');

    // Disable header, keep query
    await expect(
      got(url, {
        resolveBodyOnly: true,
        searchParams: { 
          access_token: 'token',
          checkHeader: 'false',
          checkBody: 'false'
        },
      })
    ).resolves.toEqual('token');
  });
});
