import nock from 'nock';
import sinon from 'sinon';
import { discover as discovery } from '../src';

const success = { issuer: 'https://op.example.com' };

const discover = (
  uri: string,
  timeoutDuration = 5000,
  cacheMaxAge = 600000
) => {
  const getDiscovery = discovery({
    issuerBaseURL: uri,
    timeoutDuration,
    cacheMaxAge,
  });
  return getDiscovery();
};

const mins = 60000;

describe('discover', () => {
  afterEach(nock.cleanAll);

  it('gets discovery metadata for custom /.well-known', async () => {
    nock('https://op.example.com')
      .get('/.well-known/example-configuration')
      .reply(200, success);

    await expect(
      discover('https://op.example.com/.well-known/example-configuration')
    ).resolves.toMatchObject(success);
  });

  it('gets discovery metadata for openid-configuration', async () => {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, success);

    await expect(
      discover('https://op.example.com/.well-known/openid-configuration')
    ).resolves.toMatchObject(success);
  });

  it('gets discovery metadata for openid-configuration with base url', async () => {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, success);

    await expect(discover('https://op.example.com')).resolves.toMatchObject(
      success
    );
  });

  it('gets discovery metadata for openid-configuration with path (with trailing slash)', async () => {
    nock('https://op.example.com')
      .get('/oidc/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://op.example.com/oidc',
      });

    await expect(
      discover('https://op.example.com/oidc/')
    ).resolves.toMatchObject({
      issuer: 'https://op.example.com/oidc',
    });
  });

  it('gets discovery metadata for openid-configuration with path (without trailing slash)', async () => {
    nock('https://op.example.com')
      .get('/oidc/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://op.example.com/oidc',
      });

    await expect(
      discover('https://op.example.com/oidc')
    ).resolves.toMatchObject({
      issuer: 'https://op.example.com/oidc',
    });
  });

  it('gets discovery metadata for openid-configuration with path and query', async () => {
    nock('https://op.example.com')
      .get('/oidc/.well-known/openid-configuration')
      .query({ foo: 'bar' })
      .reply(200, {
        issuer: 'https://op.example.com/oidc',
      });

    await expect(
      discover(
        'https://op.example.com/oidc/.well-known/openid-configuration?foo=bar'
      )
    ).resolves.toMatchObject({
      issuer: 'https://op.example.com/oidc',
    });
  });

  it('gets discovery metadata for oauth-authorization-server', async () => {
    nock('https://op.example.com')
      .get('/.well-known/oauth-authorization-server')
      .reply(200, success);

    await expect(
      discover('https://op.example.com/.well-known/oauth-authorization-server')
    ).resolves.toMatchObject(success);
  });

  it('gets discovery metadata for oauth-authorization-server with base url', async () => {
    nock('https://op.example.com')
      .get('/.well-known/oauth-authorization-server')
      .reply(200, success);

    await expect(discover('https://op.example.com')).resolves.toMatchObject(
      success
    );
  });

  it('gets discovery metadata for oauth-authorization-server with path (with trailing slash)', async () => {
    nock('https://op.example.com')
      .get('/.well-known/oauth-authorization-server/oauth2/')
      .reply(200, success);

    await expect(
      discover('https://op.example.com/oauth2/')
    ).resolves.toMatchObject(success);
  });

  it('gets discovery metadata for oauth-authorization-server with path (without trailing slash)', async () => {
    nock('https://op.example.com')
      .get('/.well-known/oauth-authorization-server/oauth2')
      .reply(200, success);

    await expect(
      discover('https://op.example.com/oauth2')
    ).resolves.toMatchObject(success);
  });

  it('gets discovery metadata for oauth-authorization-server with path and query', async () => {
    nock('https://op.example.com')
      .get('/.well-known/oauth-authorization-server/oauth2')
      .query({ foo: 'bar' })
      .reply(200, success);

    await expect(
      discover(
        'https://op.example.com/.well-known/oauth-authorization-server/oauth2?foo=bar'
      )
    ).resolves.toMatchObject(success);
  });

  it('is rejected when both Metadata endpoints fail', async () => {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(500)
      .get('/.well-known/oauth-authorization-server')
      .reply(200, '');

    await expect(discover('https://op.example.com')).rejects.toThrowError(
      'Failed to fetch authorization server metadata'
    );
  });

  it('is rejected when .well-known Metadata endpoint fails', async () => {
    nock('https://op.example.com')
      .get('/.well-known/example-configuration')
      .reply(500);

    await expect(
      discover('https://op.example.com/.well-known/example-configuration')
    ).rejects.toThrowError(
      'Failed to fetch https://op.example.com/.well-known/example-configuration, responded with 500'
    );
  });

  it('is rejected when .well-known Metadata endpoint responds with non JSON response', async () => {
    nock('https://op.example.com')
      .get('/.well-known/example-configuration')
      .reply(200, '');

    await expect(
      discover('https://op.example.com/.well-known/example-configuration')
    ).rejects.toThrowError(
      'Failed to parse the response from https://op.example.com/.well-known/example-configuration'
    );
  });

  it('is rejected with Error when no absolute URL is provided', async () => {
    await expect(
      discover('op.example.com/.well-known/foobar')
    ).rejects.toThrowError('Invalid URL');
  });

  it('is rejected when .well-known Metadata does not provide the required "issuer" property', async () => {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {});

    await expect(
      discover('https://op.example.com/.well-known/openid-configuration')
    ).rejects.toThrowError(
      "'issuer' not found in authorization server metadata"
    );
  });

  it('should cache discovery calls', async function () {
    const spy = jest.fn(() => success);
    nock('https://op.example.com')
      .persist()
      .get('/.well-known/openid-configuration')
      .reply(200, spy);

    const getDiscovery = discovery({
      issuerBaseURL: 'https://op.example.com/.well-known/openid-configuration',
      timeoutDuration: 5000,
      cacheMaxAge: 600000,
    });

    await getDiscovery();
    await getDiscovery();
    await getDiscovery();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('should handle concurrent discovery calls', async function () {
    const spy = jest.fn(() => success);
    nock('https://op.example.com')
      .persist()
      .get('/.well-known/openid-configuration')
      .reply(200, spy);

    const getDiscovery = discovery({
      issuerBaseURL: 'https://op.example.com/.well-known/openid-configuration',
      timeoutDuration: 5000,
      cacheMaxAge: 10 * mins,
    });

    await Promise.all([getDiscovery(), getDiscovery(), getDiscovery()]);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('should make new calls after max age', async function () {
    const clock = sinon.useFakeTimers({
      toFake: ['Date'],
    });
    const spy = jest.fn(() => success);
    nock('https://op.example.com')
      .persist()
      .get('/.well-known/openid-configuration')
      .reply(200, spy);

    const getDiscovery = discovery({
      issuerBaseURL: 'https://op.example.com/.well-known/openid-configuration',
      timeoutDuration: 5000,
      cacheMaxAge: 10 * mins,
    });

    await getDiscovery();
    expect(spy).toHaveBeenCalledTimes(1);
    clock.tick(5 * mins);
    await getDiscovery();
    expect(spy).toHaveBeenCalledTimes(1);

    clock.tick(10 * mins);
    await getDiscovery();
    expect(spy).toHaveBeenCalledTimes(2);

    clock.restore();
  });

  it('should not cache failed discovery calls', async function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(500);
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, () => success);

    const getDiscovery = discovery({
      issuerBaseURL: 'https://op.example.com/.well-known/openid-configuration',
      timeoutDuration: 5000,
      cacheMaxAge: 600000,
    });

    await expect(getDiscovery()).rejects.toThrowError();
    await expect(getDiscovery()).resolves.toMatchObject(success);
  });

  it('should handle concurrent client calls with failures', async function () {
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(500);
    nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, () => success);

    const getDiscovery = discovery({
      issuerBaseURL: 'https://op.example.com/.well-known/openid-configuration',
      timeoutDuration: 5000,
      cacheMaxAge: 600000,
    });

    await Promise.all([
      expect(getDiscovery()).rejects.toThrowError(),
      expect(getDiscovery()).rejects.toThrowError(),
      expect(getDiscovery()).rejects.toThrowError(),
    ]);
    await expect(getDiscovery()).resolves.toMatchObject(success);
  });
});
