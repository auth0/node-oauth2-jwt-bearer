
import { InvalidRequestError, UnauthorizedError } from 'oauth2-bearer';
import tokenVerifier, { type DPoPOptions, AuthError, AuthOptions } from '../src/token-verifier';
import type { VerifyJwtResult } from '../src/jwt-verifier';
import sinon from 'sinon';
import * as dpopVerifier from '../src/dpop-verifier';

const createJwtResult = (payload: any, token?: string ): VerifyJwtResult => ({
  token: token || 'abc.def.ghi',
  header: { alg: 'ES256', typ: 'JWT' },
  payload
});

const createRequest = (overrides: any = {}) => ({
  headers: {},
  url: 'https://api.example.com/resource',
  method: 'GET',
  ...overrides
});

describe('tokenVerifier', () => {
  let verifyJwt: sinon.SinonStub;
  let defaultDPoPOptions: DPoPOptions;

  beforeEach(() => {
    verifyJwt = sinon.stub();

    // Return the same JWT string passed in, with a hardcoded payload
    verifyJwt.callsFake((jwt: string) =>
      Promise.resolve({
        token: jwt,
        header: { alg: 'ES256', typ: 'JWT' },
        payload: { sub: 'user' }
      })
    );
    
    defaultDPoPOptions = { enabled: true, required: false };
  });

  afterEach(() => {
    sinon.restore();
    verifyJwt.resetHistory();
  });

  it('covers all requestOptions fields when present', async () => {
    const requestOptions = {
      url: 'https://api.example.com/resource',
      method: 'POST',
      query: { access_token: 'abc' },
      body: { access_token: 'abc' },
      isUrlEncoded: true,
      headers: { authorization: 'Bearer abc' }
    };
  
    const verifyJwt = sinon.stub().resolves({
      token: 'abc',
      header: { alg: 'RS256' },
      payload: { sub: 'user' }
    });
  
    const result = tokenVerifier(verifyJwt, {}, requestOptions);
    expect(result).toBeDefined();
    expect(typeof result.verify).toBe('function');
    expect(typeof result.applyAuthChallenges).toBe('function');
  });

  it('covers fallback branches when requestOptions and authOptions fields are missing', async () => {
    const authOptions = undefined
    const requestOptions = undefined;
  
    const verifyJwt = sinon.stub().resolves({
      token: 'abc',
      header: { alg: 'RS256' },
      payload: { sub: 'user' }
    });
  
    const result = tokenVerifier(verifyJwt, authOptions, requestOptions as any);
    expect(result).toBeDefined();
    expect(typeof result.verify).toBe('function');
    expect(typeof result.applyAuthChallenges).toBe('function');
  });  

  it('extracts token from Authorization header', async () => {
    const request = createRequest({
      headers: { authorization: 'Bearer abc.def.ghi' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    const result = await verifier.verify();
    expect(result).toHaveProperty('token', 'abc.def.ghi');
  });
  
  it('handles null headers gracefully', async () => {
    const request = createRequest({ headers: null });
    const verifier = tokenVerifier(verifyJwt, {}, request);
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });

  it('handles non-object headers gracefully', async () => {
    const request = createRequest({ headers: 'not-an-object' });
    const verifier = tokenVerifier(verifyJwt, {}, request);
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });  

  it('extracts token from query if no Authorization header', async () => {
    const accessToken = 'xyz.abc.123';
    const request = createRequest({
      query: { access_token: accessToken }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    const result = await verifier.verify();
    expect(result.token).toBe(accessToken);
  });

  it('extracts token from body when access_token is present and isUrlEncoded is true', async () => {
    const jwt = 'xyz.abc.123';
    const request = createRequest({
      body: { access_token: jwt },
      isUrlEncoded: true
    });
  
    verifyJwt.resolves(createJwtResult({ sub: 'user' }, jwt));
  
    const verifier = tokenVerifier(verifyJwt, {}, request);
    const result = await verifier.verify();
  
    expect(result.token).toBe(jwt);
  });
  

  it('throws error if multiple token locations are present', async () => {
    const request = createRequest({
      headers: { authorization: 'Bearer abc.def.ghi' },
      query: { access_token: 'other.token' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    await expect(verifier.verify()).rejects.toThrow(InvalidRequestError);
  });

  it('throws error if unknown auth scheme when DPoP is enabled', async () => {
    const request = createRequest({
      headers: { authorization: 'Unknown abc.def.ghi' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });

  it('throws UnauthorizedError if scheme is not bearer and DPoP is disabled', async () => {
    const jwt = 'abc.def.ghi';
    const headers = {
      authorization: 'DPoP something'
    };
  
    const request = createRequest({ headers });
    verifyJwt.resolves(createJwtResult({ sub: 'user' }, jwt));
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: false } }, request);
  
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });

  it('throws UnauthorizedError if scheme is unsupported and DPoP is enabled but not required', async () => {
    const jwt = 'abc.def.ghi';
    const headers = {
      authorization: 'random something'
    };
  
    const request = createRequest({
      headers,
      query: { access_token: 'something' }
     });
    verifyJwt.resolves(createJwtResult({ sub: 'user' }, jwt));
  
    const verifier = tokenVerifier(
      verifyJwt,
      {
        dpop: { enabled: true, required: false }
      },
      request
    );
  
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });    

  it('does not call verifyDPoP if token is unbound and no DPoP header present', async () => {
    const unboundToken = createJwtResult({ sub: 'user' });
    verifyJwt.resolves(unboundToken);
    const request = createRequest({
      headers: { authorization: 'Bearer abc.def.ghi' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    const result = await verifier.verify();
    expect(result.token).toEqual('abc.def.ghi');
  });

  it('applies both Bearer and DPoP challenge if no scheme and DPoP optional', () => {
    const err = new UnauthorizedError();
    const request = createRequest({});
    const verifier = tokenVerifier(verifyJwt, { dpop: defaultDPoPOptions }, request);
    const updatedErr = verifier.applyAuthChallenges(err);
    expect(updatedErr).toHaveProperty('headers');
    expect((updatedErr as AuthError).headers['WWW-Authenticate']).toMatch(/Bearer/);
    expect((updatedErr as AuthError).headers['WWW-Authenticate']).toMatch(/DPoP/);
  });

  it('should contain only Bearer challenge when DPoP is disabled', () => {
    const err = new UnauthorizedError();
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: false } }, createRequest({}));
    const result = verifier.applyAuthChallenges(err);
    expect(result).toHaveProperty('headers');
    expect((result as AuthError).headers['WWW-Authenticate']).toMatch(/Bearer/);
  });

  it('applies only DPoP challenge in required mode', () => {
    const err = new UnauthorizedError();
    const request = createRequest({
      headers: { authorization: 'DPoP abc.def', dpop: 'proof.jwt' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true, required: true } }, request);
    const result = verifier.applyAuthChallenges(err);
    expect((result as AuthError).headers['WWW-Authenticate']).toMatch(/^DPoP/);
  });

  it('throws if scheme is dpop but DPoP header is missing', async () => {
    const request = createRequest({
      headers: { authorization: 'DPoP abc.def.ghi' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true } }, request);
    await expect(verifier.verify()).rejects.toThrow(InvalidRequestError);
  });

  it('throws if scheme is bearer but DPoP header is present', async () => {
    const request = createRequest({
      headers: {
        authorization: 'Bearer abc.def.ghi',
        dpop: 'proof.jwt'
      }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true } }, request);
    await expect(verifier.verify()).rejects.toThrow(InvalidRequestError);
  });

  it('returns a valid token when DPoP is required and valid DPoP header is present', async () => {
    const dpopToken = createJwtResult({
      sub: 'user',
      cnf: { jkt: 'jkt-thumbprint' }
    });
    verifyJwt.resolves(dpopToken);

    const verifyDPoP = sinon.stub(dpopVerifier, 'verifyDPoP').resolves();

    const request = createRequest({
      headers: {
        authorization: 'DPoP abc.def.ghi',
        dpop: 'proof.jwt'
      }
    });

    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true, required: true } }, request);
    const result = await verifier.verify();
    expect(result.token).toBe('abc.def.ghi');

    verifyDPoP.restore();
  });
  
  it('throws error if DPoP is required but no DPoP header is present', async () => {
    const request = createRequest({
      headers: { authorization: 'DPoP abc.def.ghi' }
    });
  
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true, required: true } }, request);
    await expect(verifier.verify()).rejects.toThrow(InvalidRequestError);
  });
  
  it('should not throw error when DPoP is disabled but DPoP header is present', async () => {
    const request = createRequest({
      headers: {
        authorization: 'Bearer abc.def.ghi',
        dpop: 'proof.jwt'
      }
    });
  
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: false } }, request);
    const result = await verifier.verify();
    expect(result.token).toBe('abc.def.ghi');
  });
  
  it('applies both Bearer and DPoP challenges if no scheme and DPoP optional', () => {
    const err = new UnauthorizedError();
    const request = createRequest({});
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true } }, request);
    const updatedErr = verifier.applyAuthChallenges(err);
    expect(updatedErr).toHaveProperty('headers');
    expect((updatedErr as AuthError).headers['WWW-Authenticate']).toMatch(/Bearer/);
    expect((updatedErr as AuthError).headers['WWW-Authenticate']).toMatch(/DPoP/);
  });
  
  it('applies only DPoP challenge in required mode', () => {
    const err = new UnauthorizedError();
    const request = createRequest({
      headers: { authorization: 'DPoP abc.def', dpop: 'proof.jwt' }
    });
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true, required: true } }, request);
    const result = verifier.applyAuthChallenges(err);
    expect((result as AuthError).headers['WWW-Authenticate']).toMatch(/^DPoP/);
  });
  
  it('throws error if token is missing and DPoP is required', async () => {
    const request = createRequest({
      headers: { dpop: 'proof.jwt' }
    });
  
    const verifier = tokenVerifier(verifyJwt, { dpop: { enabled: true, required: true } }, request);
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });
  
  it('throws error if unsupported auth scheme is used', async () => {
    const request = createRequest({
      headers: { authorization: 'Basic abc.def.ghi' }
    });
  
    const verifier = tokenVerifier(verifyJwt, {}, request);
    await expect(verifier.verify()).rejects.toThrow(UnauthorizedError);
  });

  it('adds DPoP only challenges when DPoP is enabled in "required" mode.', () => {
    const options: AuthOptions = {
      dpop: { enabled: true, required: true }
    };
  
    const verifier = tokenVerifier(() => Promise.resolve(createJwtResult({})), options, {
      headers: {
        authorization: 'DPoP abc',
        dpop: 'proof'
      },
      method: 'POST',
      url: 'https://api.example.com'
    });
  
    const error = new UnauthorizedError('unauthorized');
    (error as AuthError).code = 'invalid_token';
  
    const result = verifier.applyAuthChallenges(error);
  
    expect(result).toBeInstanceOf(UnauthorizedError);
    expect((result as UnauthorizedError).headers['WWW-Authenticate']).toContain(
      'DPoP error="invalid_token", error_description="unauthorized", algs="ES256"'
    );
  });

  it('adds both DPoP and Bearer challenges when DPoP is enabled in "allowed" mode.', () => {
    const options: AuthOptions = {
      dpop: { enabled: true, required: false }
    };
  
    const verifier = tokenVerifier(() => Promise.resolve(createJwtResult({})), options, {
      headers: {
        authorization: 'DPoP abc',
        dpop: 'proof'
      },
      method: 'POST',
      url: 'https://api.example.com'
    });
  
    const error = new UnauthorizedError('unauthorized');
    (error as AuthError).code = 'invalid_token';
  
    const result = verifier.applyAuthChallenges(error);
  
    expect(result).toBeInstanceOf(UnauthorizedError);
    expect((result as UnauthorizedError).headers['WWW-Authenticate']).toContain(
      'DPoP error="invalid_token", error_description="unauthorized", algs="ES256"'
    );
    expect((result as UnauthorizedError).headers['WWW-Authenticate']).toContain(
      'Bearer realm="api"'
    );
  });

  it('adds both DPoP and Bearer challenges when DPoP is enabled in "allowed" mode.', () => {
    const options: AuthOptions = {
      dpop: { enabled: true, required: false }
    };
  
    const verifier = tokenVerifier(() => Promise.resolve(createJwtResult({})), options, {
      headers: {
        authorization: 'Bearer abc',
        dpop: 'proof'
      },
      method: 'POST',
      url: 'https://api.example.com'
    });
  
    const error = new UnauthorizedError('unauthorized');
    (error as AuthError).code = 'invalid_token';
  
    const result = verifier.applyAuthChallenges(error);
  
    expect(result).toBeInstanceOf(UnauthorizedError);
    expect((result as UnauthorizedError).headers['WWW-Authenticate']).toContain(
      'Bearer realm="api", error="invalid_token", error_description="unauthorized"'
    );
    expect((result as UnauthorizedError).headers['WWW-Authenticate']).toContain(
      'DPoP algs="ES256"'
    );
  });
});
