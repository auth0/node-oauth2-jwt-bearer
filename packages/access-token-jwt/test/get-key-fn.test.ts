import { exportJWK, generateKeyPair } from 'jose';
import nock from 'nock';
import getKeyFn from '../src/get-key-fn';

describe('get-key-fn', () => {
  afterEach(nock.cleanAll);

  it('return a secret key if one is provided', async () => {
    const keyFn = getKeyFn({
      secret: 'shhh!',
      cooldownDuration: 1000,
      timeoutDuration: 1000,
      cacheMaxAge: 1000,
    });
    const key = await keyFn('foo')();
    expect(key.type).toBe('secret');
  });

  it('return a JWKS if no secret is provided', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const publicJwk = await exportJWK(publicKey);
    nock('https://issuer.example.com/')
      .persist()
      .get('/jwks.json')
      .reply(200, { keys: [{ kid: 'kid', ...publicJwk }] });
    const keyFn = getKeyFn({
      cooldownDuration: 1000,
      timeoutDuration: 1000,
      cacheMaxAge: 1000,
    });
    const key = await keyFn('https://issuer.example.com/jwks.json')({
      alg: 'RS256',
      kid: 'kid',
    });
    expect(key.type).toBe('public');
  });

  it('should cache the JWKS provider', async () => {
    const keyFn = getKeyFn({
      cooldownDuration: 1000,
      timeoutDuration: 1000,
      cacheMaxAge: 1000,
    });
    const uri = 'https://issuer.example.com/jwks.json';
    const getKeyA = keyFn(uri);
    const getKeyB = keyFn(uri);
    expect(getKeyA).toBe(getKeyB);
  });

  it('should invalidate JWKS provider cache if jwksUri changes', async () => {
    const keyFn = getKeyFn({
      cooldownDuration: 1000,
      timeoutDuration: 1000,
      cacheMaxAge: 1000,
    });
    const getKeyA = keyFn('https://issuer.example.com/jwks1.json');
    const getKeyB = keyFn('https://issuer.example.com/jwks2.json');
    const getKeyC = keyFn('https://issuer.example.com/jwks2.json');
    expect(getKeyA).not.toBe(getKeyB);
    expect(getKeyB).toBe(getKeyC);
  });
});
