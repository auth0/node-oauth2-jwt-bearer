import nock = require('nock');
import sinon = require('sinon');
import { createJwt } from './helpers';
import { jwtVerifier } from '../src';

describe('index', () => {
  afterEach(nock.cleanAll);

  it('gets metadata and verifies jwt with discovery', async () => {
    const jwt = await createJwt({ issuer: 'https://op.example.com' });

    const verify = jwtVerifier({
      issuerBaseURL: 'https://op.example.com',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toHaveProperty('payload', {
      iss: 'https://op.example.com',
      sub: 'me',
      aud: 'https://api/',
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
  });

  it('gets metadata and verifies jwt without discovery', async () => {
    const jwt = await createJwt({ issuer: 'https://op.example.com' });

    const verify = jwtVerifier({
      issuer: 'https://op.example.com',
      jwksUri: 'https://op.example.com/.well-known/jwks.json',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toHaveProperty('payload', {
      iss: 'https://op.example.com',
      sub: 'me',
      aud: 'https://api/',
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
  });

  it('caches discovery and jwks requests in memory', async () => {
    const discoverSpy = jest.fn();
    const jwksSpy = jest.fn();

    const jwt = await createJwt({
      issuer: 'https://op.example.com',
      jwksSpy,
      discoverSpy,
    });

    const verify = jwtVerifier({
      issuerBaseURL: 'https://op.example.com',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toBeTruthy();
    await expect(verify(jwt)).resolves.toBeTruthy();
    await expect(verify(jwt)).resolves.toBeTruthy();
    expect(discoverSpy).toHaveBeenCalledTimes(1);
    expect(jwksSpy).toHaveBeenCalledTimes(1);
  });

  it('handles rotated signing keys', async () => {
    // @FIXME Use jest timers when facebook/jest#10221 is fixed
    const clock = sinon.useFakeTimers();
    const jwksSpy = jest.fn();
    const oldJwt = await createJwt({
      issuer: 'https://op.example.com',
      jwksSpy,
      kid: 'a',
    });

    const verify = jwtVerifier({
      issuer: 'https://op.example.com',
      jwksUri: 'https://op.example.com/.well-known/jwks.json',
      audience: 'https://api/',
    });
    await expect(verify(oldJwt)).resolves.toBeTruthy();

    const newJwt = await createJwt({
      issuer: 'https://op.example.com',
      jwksSpy,
      kid: 'b',
    });
    // Wait for jose RemoteJWKSet default "cooldownDuration"
    clock.tick(30000);

    await expect(verify(newJwt)).resolves.toBeTruthy();
    clock.restore();
  });
});
