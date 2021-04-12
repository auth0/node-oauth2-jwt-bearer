import nock = require('nock');
import discovery from '../src/discovery';
import { createJwt } from './helpers';
import { tokenVerifier } from '../src';

describe('index', () => {
  afterEach(nock.cleanAll);

  it('gets metatdata and verifies jwt', async () => {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://op.example.com',
        jwks_uri: 'https://op.example.com/.well-known/jwks.json',
      });
    const jwt = await createJwt({ issuer: 'https://op.example.com' });

    const { issuer, jwks_uri: jwksUri } = await discovery(
      'https://op.example.com'
    );
    const verify = tokenVerifier({
      jwksUri,
      issuer,
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toMatchObject({
      iss: 'https://op.example.com',
      sub: 'me',
      aud: 'https://api/',
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
  });
});
