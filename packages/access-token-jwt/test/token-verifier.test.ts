import {
  InvalidRequestError,
  InvalidTokenError,
  UnauthorizedError,
} from 'oauth2-bearer';
import tokenVerifier, {
  type DPoPOptions,
  type AuthError,
  type AuthOptions,
  type QueryLike,
  type BodyLike,
  isJsonObject,
  normalizeHeaders,
  getAuthScheme,
  assertValidDPoPOptions,
} from '../src/token-verifier';
import {
  type VerifyJwtResult,
  type VerifyJwt,
  ASYMMETRIC_ALGS as SUPPORTED_ALGS,
} from '../src/jwt-verifier';
import sinon from 'sinon';
import * as dpopVerifier from '../src/dpop-verifier';

const createJwtResult = (payload: any, token?: string): VerifyJwtResult => ({
  token: token || 'abc.def.ghi',
  header: { alg: 'ES256', typ: 'JWT' },
  payload,
});

const createRequest = (overrides: any = {}) => ({
  headers: {
    authorization: 'bearer abc.def.ghi',
  },
  url: 'https://api.example.com/resource',
  method: 'GET',
  ...overrides,
});

const defaultVerifyJwt: VerifyJwt = () =>
  Promise.resolve({ payload: {}, header: {}, token: '' });

interface MakeVerifierOptions {
  verifyJwt?: VerifyJwt;
  dpop?: AuthOptions['dpop'];
  headers?: Record<string, unknown>;
  query?: QueryLike;
  body?: BodyLike;
  isUrlEncoded?: boolean;
  method?: string;
  url?: string;
}

export const makeVerifier = ({
  verifyJwt = defaultVerifyJwt,
  dpop,
  headers = {},
  query = {},
  body = {},
  isUrlEncoded = false,
  method = 'GET',
  url = 'https://api.example.com/protected',
}: MakeVerifierOptions = {}) => {
  return tokenVerifier(
    verifyJwt,
    { dpop },
    {
      headers,
      query,
      body,
      isUrlEncoded,
      method,
      url,
    }
  );
};

function parseWwwAuthenticate(header: string | string[]) {
  const raw = Array.isArray(header) ? header.join(', ') : header;
  const result: Record<string, Record<string, string>> = {};

  let currentScheme = '';
  let currentParams: Record<string, string> = {};

  const parts = raw.split(/,\s*/);
  for (const part of parts) {
    const schemeMatch = part.match(/^([A-Za-z]+)\s+/);
    if (schemeMatch) {
      // Store previous scheme
      if (currentScheme) {
        result[currentScheme] = currentParams;
      }

      currentScheme = schemeMatch[1];
      currentParams = {};

      const remainder = part.slice(schemeMatch[0].length).trim();
      if (remainder) {
        const [k, v] = remainder.split('=');
        currentParams[k] = v?.replace(/^"|"$/g, '');
      }
    } else {
      const [k, v] = part.split('=');
      if (k && v) {
        currentParams[k] = v.replace(/^"|"$/g, '');
      }
    }
  }

  // Store last parsed challenge
  if (currentScheme) {
    result[currentScheme] = currentParams;
  }

  return result;
}

describe('isJsonObject', () => {
  it('returns true for plain objects', () => {
    expect(isJsonObject({})).toBe(true);
    expect(isJsonObject({ a: 1 })).toBe(true);
    expect(isJsonObject(Object.create(null))).toBe(true);
  });

  it('returns false for null', () => {
    expect(isJsonObject(null)).toBe(false);
  });

  it('returns true for objects created with Object.create(null)', () => {
    expect(isJsonObject(Object.create(null))).toBe(true);
  });

  it('isJsonObject | returns false for Map and Set', () => {
    expect(isJsonObject(new Map())).toBe(false);
    expect(isJsonObject(new Set())).toBe(false);
  });

  it('returns false for arrays', () => {
    expect(isJsonObject([])).toBe(false);
    expect(isJsonObject([1, 2, 3])).toBe(false);
  });

  it('returns false for primitive types', () => {
    expect(isJsonObject('string')).toBe(false);
    expect(isJsonObject(123)).toBe(false);
    expect(isJsonObject(true)).toBe(false);
    expect(isJsonObject(undefined)).toBe(false);
    expect(isJsonObject(Symbol('sym'))).toBe(false);
  });

  it('returns false for functions and arrow functions', () => {
    expect(
      isJsonObject(function () {
        return true;
      })
    ).toBe(false);
    expect(
      isJsonObject(() => {
        return true;
      })
    ).toBe(false);
  });

  it('returns true for class instances (object type)', () => {
    class MyClass {}
    const instance = new MyClass();
    expect(isJsonObject(instance)).toBe(true);
  });
});

describe('normalizeHeaders', () => {
  // Note: To avoid unhandled exceptions, this function does not throw errors.
  // It returns undefined for invalid or unexpected input.
  it('returns empty object if input is not an object', () => {
    expect(normalizeHeaders(null)).toEqual({});
    expect(normalizeHeaders(undefined)).toEqual({});
    expect(normalizeHeaders('string')).toEqual({});
    expect(normalizeHeaders(123)).toEqual({});
    expect(normalizeHeaders(true)).toEqual({});
    expect(normalizeHeaders([])).toEqual({});
    expect(
      normalizeHeaders(() => {
        return true;
      })
    ).toEqual({});
  });

  it('keeps non-string values as-is', () => {
    const result = normalizeHeaders({ Foo: 1 as any, Bar: false as any });
    expect(result).toEqual({ foo: 1, bar: false });
  });

  it('converts all keys to lowercase', () => {
    const result = normalizeHeaders({
      Authorization: 'Bearer abc',
      DPoP: 'xyz',
      'Content-Type': 'application/json',
    });

    expect(result).toEqual({
      authorization: 'Bearer abc',
      dpop: 'xyz',
      'content-type': 'application/json',
    });
  });

  it('preserves values even for keys with mixed casing', () => {
    const result = normalizeHeaders({
      X_Custom_Header: 'value1',
      x_CUSTOM_HEADER: 'value2',
    });

    expect(result).toEqual({
      x_custom_header: 'value2', // last one overrides
    });
  });

  it('includes numeric keys as string keys', () => {
    const obj: any = {};
    obj[123] = 'value';
    obj['ValidKey'] = 'valid';

    const result = normalizeHeaders(obj);
    expect(result).toEqual({
      '123': 'value',
      validkey: 'valid',
    });
  });

  it('returns a new object and does not mutate the input', () => {
    const input = { Foo: 'Bar' };
    const result = normalizeHeaders(input);
    expect(result).not.toBe(input);
    expect(result).toEqual({ foo: 'Bar' });
  });

  it('works with objects created using Object.create(null)', () => {
    const input = Object.create(null);
    input.Authorization = 'Bearer abc';

    const result = normalizeHeaders(input);
    expect(result).toEqual({ authorization: 'Bearer abc' });
  });
});

describe('getAuthScheme', () => {
  // Note: To avoid unhandled exceptions, this function does not throw errors.
  // It returns undefined for invalid or unexpected input.

  it('returns undefined if headers.authorization is not a string', () => {
    expect(getAuthScheme({ authorization: undefined })).toBeUndefined();
    expect(getAuthScheme({ authorization: 123 as any })).toBeUndefined();
    expect(getAuthScheme({ authorization: null as any })).toBeUndefined();
    expect(getAuthScheme({ authorization: {} as any })).toBeUndefined();
  });

  it('returns undefined if authorization string is malformed', () => {
    expect(getAuthScheme({ authorization: '' })).toBeUndefined(); // empty string
    expect(getAuthScheme({ authorization: 'Bearer' })).toBeUndefined(); // missing token
    expect(
      getAuthScheme({ authorization: 'Bearer token extra' })
    ).toBeUndefined(); // too many parts
    expect(
      getAuthScheme({ authorization: '  DPoP    token123  ' })
    ).toBeUndefined(); // too many parts
    expect(getAuthScheme({ authorization: 'Bearer    abc' })).toBeUndefined(); // too many parts
  });

  it('returns lowercase scheme for valid input', () => {
    expect(getAuthScheme({ authorization: 'Bearer abc.def.ghi' })).toBe(
      'bearer'
    );
    expect(getAuthScheme({ authorization: 'DPoP xyz' })).toBe('dpop');
    expect(getAuthScheme({ authorization: 'PoP someToken' })).toBe('pop');
  });

  it('returns undefined if authorization is not present', () => {
    expect(getAuthScheme({})).toBeUndefined();
  });
});

describe('assertValidDPoPOptions', () => {
  it('does nothing if options are undefined', () => {
    expect(() => assertValidDPoPOptions(undefined)).not.toThrow();
  });

  it('does nothing for fully valid options', () => {
    expect(() =>
      assertValidDPoPOptions({
        enabled: true,
        required: false,
        iatOffset: 300,
        iatLeeway: 30,
      })
    ).not.toThrow();
  });

  it('throws if `options.dpop` is not an object', () => {
    expect(() => assertValidDPoPOptions(null as any)).toThrowError(
      'Invalid DPoP configuration: "dpop" must be an object'
    );
    expect(() => assertValidDPoPOptions([] as any)).toThrowError(
      'Invalid DPoP configuration: "dpop" must be an object'
    );
    expect(() => assertValidDPoPOptions(123 as any)).toThrowError(
      'Invalid DPoP configuration: "dpop" must be an object'
    );
    expect(() => assertValidDPoPOptions('invalid' as any)).toThrowError(
      'Invalid DPoP configuration: "dpop" must be an object'
    );
  });

  it('throws if enabled is not a boolean', () => {
    expect(() =>
      assertValidDPoPOptions({ enabled: 'yes' } as any)
    ).toThrowError('Invalid DPoP option: "enabled" must be a boolean');
  });

  it('throws if required is not a boolean', () => {
    expect(() => assertValidDPoPOptions({ required: 1 } as any)).toThrowError(
      'Invalid DPoP option: "required" must be a boolean'
    );
  });

  it('throws if iatOffset is not a number', () => {
    expect(() =>
      assertValidDPoPOptions({ iatOffset: '300' } as any)
    ).toThrowError('Invalid DPoP option: "iatOffset" must be a number');
  });

  it('throws if iatOffset is negative', () => {
    expect(() => assertValidDPoPOptions({ iatOffset: -100 })).toThrowError(
      'Invalid DPoP option: "iatOffset" must be a non-negative number'
    );
  });

  it('throws if iatLeeway is not a number', () => {
    expect(() =>
      assertValidDPoPOptions({ iatLeeway: '30' } as any)
    ).toThrowError('Invalid DPoP option: "iatLeeway" must be a number');
  });

  it('throws if iatLeeway is negative', () => {
    expect(() => assertValidDPoPOptions({ iatLeeway: -5 })).toThrowError(
      'Invalid DPoP option: "iatLeeway" must be a non-negative number'
    );
  });

  it('throws if required is true but enabled is false', () => {
    expect(() =>
      assertValidDPoPOptions({ enabled: false, required: true })
    ).toThrowError(
      'Invalid DPoP configuration: cannot set "required" to true when "enabled" is false'
    );
  });

  it('allows partial valid config', () => {
    expect(() => assertValidDPoPOptions({ enabled: true })).not.toThrow();
    expect(() => assertValidDPoPOptions({ required: false })).not.toThrow();
    expect(() => assertValidDPoPOptions({ iatOffset: 0 })).not.toThrow();
    expect(() => assertValidDPoPOptions({ iatLeeway: 0 })).not.toThrow();
    expect(() => assertValidDPoPOptions({ iatLeeway: 0 })).not.toThrow();
  });
});

describe('tokenVerifier / validateRequestOptions', () => {
  let verifyJwt: sinon.SinonStub;
  let defaultDPoPOptions: DPoPOptions;

  beforeEach(() => {
    verifyJwt = sinon.stub();

    // Return the same JWT string passed in, with a hardcoded payload
    verifyJwt.callsFake((jwt: string) =>
      Promise.resolve({
        token: jwt,
        header: { alg: 'ES256', typ: 'JWT' },
        payload: { sub: 'user' },
      })
    );

    defaultDPoPOptions = { enabled: true, required: false };
  });

  afterEach(() => {
    sinon.restore();
    verifyJwt.resetHistory();
  });

  async function expectInvalidRequest({
    request,
    expectedMessage,
  }: {
    request: Record<string, any>;
    expectedMessage: string;
  }) {
    const verifier = tokenVerifier(
      verifyJwt,
      { dpop: defaultDPoPOptions },
      createRequest(request)
    );
    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw');
    } catch (err) {
      // Note: In this context, error will not contain DPoP challenge headers.
      // Because DPoP headers will be added later once the error is caught by the main `catch` block in the auth middleware.

      expect(err.constructor).toBe(InvalidRequestError);
      expect(err.message).toBe(expectedMessage);

      const headers = err.headers;
      expect(headers).toBeDefined();
      expect(headers).toHaveProperty('WWW-Authenticate');

      const challenge = headers['WWW-Authenticate'];
      expect(typeof challenge).toBe('string');
      expect(challenge).toMatch(/^Bearer/);

      const parsed = parseWwwAuthenticate(challenge);
      expect(parsed.Bearer?.error).toBe('invalid_request');
      expect(parsed.Bearer?.error_description).toBe(expectedMessage);
    }
  }

  it('throws error if request options is not an object (covering bad request)', async () => {
    const verifyJwt = jest
      .fn()
      .mockResolvedValue(createJwtResult({ sub: 'user' }));
    const verifier = tokenVerifier(verifyJwt, undefined, undefined as any);

    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw');
    } catch (err) {
      expect(err.constructor).toBe(InvalidRequestError);
      expect(err.message).toBe('Invalid request URL');
    }
    expect(verifyJwt).not.toHaveBeenCalled();
  });

  it('throws error if request `url` is not a string', async () => {
    await expectInvalidRequest({
      request: { url: 12345 }, // invalid URL type
      expectedMessage: 'Invalid request URL',
    });
  });

  it('throws error if request `url` is an empty string', async () => {
    await expectInvalidRequest({
      request: { url: '' }, // empty string URL
      expectedMessage: 'Invalid request URL',
    });
  });

  it('throws error if request `method` is not a string', async () => {
    await expectInvalidRequest({
      request: { method: 12345 }, // invalid method type
      expectedMessage: 'Invalid HTTP method received in request',
    });
  });

  it('throws error if request `method` is an empty string', async () => {
    await expectInvalidRequest({
      request: { method: '' }, // empty string method
      expectedMessage: 'Invalid HTTP method received in request',
    });
  });

  it('throws error if request `query` exists but is not an object', async () => {
    await expectInvalidRequest({
      request: { query: 'random_string' }, // invalid query type
      expectedMessage: "Request 'query' parameter must be a valid JSON object",
    });
  });

  it('throws error if request `body` exists but is not an object', async () => {
    await expectInvalidRequest({
      request: { body: 'random_string' }, // invalid body type
      expectedMessage: "Request 'body' parameter must be a valid JSON object",
    });
  });
});

describe('tokenVerifier / shouldVerifyDPoP', () => {
  it('"allowed" mode | returns true if Authorization scheme is DPoP', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      headers: { authorization: 'DPoP token123' },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(true);
  });

  it('"allowed" mode | returns true if the access token has cnf.jkt (DPoP-bound token) with DPoP scheme', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      headers: { authorization: 'dpop abc.def' },
    });
    expect(verifier.shouldVerifyDPoP({ cnf: { jkt: 'abc' } })).toBe(true);
  });

  it('"allowed" mode | returns true if the access token has cnf.jkt (DPoP-bound token) with Bearer scheme', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      headers: { authorization: 'bearer abc.def' },
    });
    expect(verifier.shouldVerifyDPoP({ cnf: { jkt: 'abc' } })).toBe(true);
  });

  it('"allowed" mode | returns true if DPoP proof header is present', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      headers: { dpop: 'proof.jwt.here' },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(true);
  });

  it('"allowed" mode | returns false if none of the conditions are met', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(false);
  });

  it('"disabled" mode | returns false when DPoP is disabled', () => {
    const verifier = makeVerifier({
      dpop: { enabled: false },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(false);
  });

  it('"disabled" mode | returns false when DPoP is disabled, but contains a DPoP proof header', () => {
    const verifier = makeVerifier({
      dpop: { enabled: false },
      headers: { dpop: 'proof.jwt.here' },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(false);
  });

  it('"disabled" mode | returns false when DPoP is disabled, but contains a DPoP HTTP authentication scheme', () => {
    const verifier = makeVerifier({
      dpop: { enabled: false },
      headers: { authorization: 'DPoP token123' },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(false);
  });

  it('"required" mode | returns true when DPoP is enabled and required', () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: true },
    });
    expect(verifier.shouldVerifyDPoP({})).toBe(true);
  });
});

describe('tokenVerifier / getToken', () => {
  const expectGetTokenToThrow = (
    config: {
      headers?: Record<string, unknown>;
      query?: QueryLike;
      body?: BodyLike;
      isUrlEncoded?: boolean;
    },
    expectedError: new (...args: any[]) => Error,
    expectedMessage: string
  ) => {
    const verifier = makeVerifier({
      dpop: {},
      ...config,
    });

    try {
      verifier.getToken();
      throw new Error('Expected getToken() to throw');
    } catch (e) {
      expect(e.constructor).toBe(expectedError);
      expect(e.message).toBe(expectedMessage);
    }
  };

  it('extracts token from Authorization header (Bearer)', () => {
    const token = makeVerifier({
      headers: { authorization: 'Bearer abc.def.ghi' },
    }).getToken();
    expect(token).toEqual({ location: 'header', jwt: 'abc.def.ghi' });
  });

  it('extracts token from Authorization header (DPoP)', () => {
    const token = makeVerifier({
      headers: { authorization: 'DPoP xyz.123.jwt' },
    }).getToken();
    expect(token).toEqual({ location: 'header', jwt: 'xyz.123.jwt' });
  });

  it('extracts token from query param', () => {
    const token = makeVerifier({
      query: { access_token: 'abc.def.hgi' },
    }).getToken();
    expect(token).toEqual({ location: 'query', jwt: 'abc.def.hgi' });
  });

  it('extracts token from urlencoded body', () => {
    const token = makeVerifier({
      body: { access_token: 'abc.def.hgi' },
      isUrlEncoded: true,
    }).getToken();
    expect(token).toEqual({ location: 'body', jwt: 'abc.def.hgi' });
  });

  it('throws if no token is provided anywhere', () => {
    expectGetTokenToThrow({}, UnauthorizedError, 'Unauthorized');
  });

  it('throws if empty token in Authorization', () => {
    expectGetTokenToThrow(
      { headers: { authorization: 'Bearer ' } },
      UnauthorizedError,
      'Unauthorized'
    );
  });

  it('should not throw if empty token in query', () => {
    const token = makeVerifier({
      query: { access_token: '' },
    }).getToken();
    expect(token).toEqual({ location: 'query', jwt: '' });
  });

  it('should not throw if empty token in body when isUrlEncoded is true', () => {
    const token = makeVerifier({
      body: { access_token: '' },
      isUrlEncoded: true,
    }).getToken();
    expect(token).toEqual({ location: 'body', jwt: '' });
  });

  it('throws if empty token in body when isUrlEncoded is false', () => {
    expectGetTokenToThrow(
      { body: { access_token: '' }, isUrlEncoded: false },
      UnauthorizedError,
      'Unauthorized'
    );
  });

  it('throws if multiple token sources are used (header + query)', () => {
    expectGetTokenToThrow(
      {
        headers: { authorization: 'Bearer abc.def.ghi' },
        query: { access_token: 'abc.def.hgi' },
      },
      InvalidRequestError,
      'More than one method used for authentication'
    );
  });

  it('throws if multiple token sources are used (query + body)', () => {
    expectGetTokenToThrow(
      {
        query: { access_token: 'abc.def.hgi' },
        body: { access_token: 'abc.def.hgi' },
        isUrlEncoded: true,
      },
      InvalidRequestError,
      'More than one method used for authentication'
    );
  });

  it('throws if multiple token sources are used (header + body) with `isUrlEncoded: true`', () => {
    expectGetTokenToThrow(
      {
        headers: { authorization: 'Bearer abc.def.hgi' },
        body: { access_token: 'abc.def.hgi' },
        isUrlEncoded: true,
      },
      InvalidRequestError,
      'More than one method used for authentication'
    );
  });

  it("doesn't throw when token is sent via (header + body) but `isUrlEncoded: false`", () => {
    const token = makeVerifier({
      headers: { authorization: 'Bearer abc.def.hgi' },
      body: { access_token: 'abc.def.hgi' },
      isUrlEncoded: false,
    }).getToken();

    // When isUrlEncoded is false, the body is not considered a valid token source,
    // so having both header + body does not count as multiple sources.
    expect(token).toEqual({ location: 'header', jwt: 'abc.def.hgi' });
  });

  it('throws if malformed authorization header', () => {
    expectGetTokenToThrow(
      {
        headers: { authorization: 'badtoken' },
      },
      UnauthorizedError,
      'Unauthorized'
    );
  });

  it('throws if authorization header is not a string', () => {
    expectGetTokenToThrow(
      {
        headers: { authorization: 12345 },
      },
      UnauthorizedError,
      'Unauthorized'
    );
  });
});

describe('tokenVerifier / applyAuthChallenges', () => {
  const makeInvalidRequestError = (
    msg: string,
    code = 'invalid_request'
  ): InvalidRequestError => {
    const e = new InvalidRequestError(msg);
    e.code = code;
    return e;
  };

  const makeUnauthorizedError = (msg: string): UnauthorizedError => {
    return new UnauthorizedError(msg);
  };

  it('"allowed" mode | returns original error if the error is not an instance of UnauthorizedError', () => {
    const err = new Error('fail');
    const verifier = makeVerifier({ dpop: { enabled: true } });
    expect(verifier.applyAuthChallenges(err)).toBe(err);
  });

  it('"allowed" mode | returns Bearer + DPoP challenges when auth scheme is bearer', () => {
    const error = makeInvalidRequestError('Invalid request');
    const verifier = makeVerifier({
      headers: { authorization: 'Bearer abc' },
      dpop: { enabled: true, required: false },
    });

    const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
    expect(e.headers?.['WWW-Authenticate']).toBe(
      `Bearer realm="api", error="invalid_request", error_description="Invalid request", DPoP algs="${SUPPORTED_ALGS.join(
        ' '
      )}"`
    );
  });

  it('"allowed" mode | returns Bearer + DPoP challenges when auth scheme is dpop', () => {
    const error = makeInvalidRequestError('Invalid DPoP');
    const verifier = makeVerifier({
      headers: { authorization: 'DPoP abc' },
      dpop: { enabled: true, required: false },
    });

    const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
    expect(e.headers?.['WWW-Authenticate']).toBe(
      `DPoP error="invalid_request", error_description="Invalid DPoP", algs="${SUPPORTED_ALGS.join(
        ' '
      )}", Bearer realm="api"`
    );
  });

  it('"allowed" mode | returns Bearer + DPoP challenges when no auth scheme and token was from query', () => {
    const error = makeUnauthorizedError('Unauthorized error');
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      method: 'POST',
      query: { access_token: 'abc.def.ghi' },
      headers: {},
      isUrlEncoded: false,
    });

    const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
    expect(e.headers?.['WWW-Authenticate']).toBe(
      `Bearer realm="api", DPoP algs="${SUPPORTED_ALGS.join(' ')}"`
    );
    expect(e.headers?.['WWW-Authenticate']).not.toContain(
      'error="unauthorized"'
    );
  });

  it('"allowed" mode | does not add error attributes in challenges if authScheme is neither dpop nor bearer', () => {
    const error = makeInvalidRequestError('Unsupported scheme');
    const verifier = makeVerifier({
      headers: { authorization: 'mac abc' },
      dpop: { enabled: true, required: false },
    });

    const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
    expect(e.headers?.['WWW-Authenticate']).toBe(
      `Bearer realm="api", DPoP algs="${SUPPORTED_ALGS.join(' ')}"`
    );
    expect(e.headers?.['WWW-Authenticate']).not.toContain('error=');
  });

  it('"allowed" mode | only Bearer challenge has error fields when scheme is unknown but token is from query (InvalidTokenError)', async () => {
    const mockVerifyJwt = jest
      .fn()
      .mockRejectedValue(new InvalidTokenError('Invalid token'));
    const verifier = makeVerifier({
      verifyJwt: mockVerifyJwt,
      dpop: { enabled: true, required: false },
      query: { access_token: 'abc.def.ghi' },
    });

    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw');
    } catch (error) {
      const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
      expect(e.headers?.['WWW-Authenticate']).toBe(
        `Bearer realm="api", error="invalid_token", error_description="Invalid token", DPoP algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`
      );
    }
  });

  it('"allowed" mode | only Bearer challenge has error fields when scheme is unknown but token is from body (InvalidTokenError)', async () => {
    const mockVerifyJwt = jest
      .fn()
      .mockRejectedValue(new InvalidTokenError('Invalid token'));

    const verifier = makeVerifier({
      verifyJwt: mockVerifyJwt,
      dpop: { enabled: true, required: false },
      body: { access_token: 'abc.def.ghi' },
      isUrlEncoded: true,
    });

    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw');
    } catch (error) {
      const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
      expect(e.headers?.['WWW-Authenticate']).toBe(
        `Bearer realm="api", error="invalid_token", error_description="Invalid token", DPoP algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`
      );
    }
  });

  it('"allowed" mode | does not add error attributes in challenges when scheme is unknown and token is from body (UnauthorizedError) but isUrlEncoded is false', async () => {
    const verifier = makeVerifier({
      dpop: { enabled: true, required: false },
      body: { access_token: 'abc.def.ghi' },
      isUrlEncoded: false,
    });

    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw');
    } catch (error) {
      const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
      expect(e).toBeInstanceOf(UnauthorizedError);
      expect(e.headers?.['WWW-Authenticate']).toBe(
        `Bearer realm="api", DPoP algs="${SUPPORTED_ALGS.join(' ')}"`
      );
    }
  });

  it('"disabled" mode | returns original error if DPoP is disabled', () => {
    const error = new UnauthorizedError('unauth');
    const verifier = makeVerifier({
      dpop: { enabled: false },
    });

    expect(verifier.applyAuthChallenges(error)).toBe(error);
  });

  it('"required" mode | returns only DPoP challenge with error fields', () => {
    const error = makeInvalidRequestError('Missing proof');
    const verifier = makeVerifier({
      headers: { authorization: 'DPoP abc' },
      dpop: { enabled: true, required: true },
    });

    const e = verifier.applyAuthChallenges(error) as UnauthorizedError;
    expect(e.headers?.['WWW-Authenticate']).toBe(
      `DPoP error="invalid_request", error_description="Missing proof", algs="${SUPPORTED_ALGS.join(
        ' '
      )}"`
    );
  });
});

describe('tokenVerifier / verify', () => {
  const dummyJwt = 'abc.def.ghi';
  const baseRequest = {
    url: 'https://api.example.com/resource',
    method: 'GET',
    headers: {},
  };

  async function expectVerifyToThrow({
    verifier,
    expectedError,
    expectedMessage,
    expectedCode,
    expectedChallengeIncludes,
  }: {
    verifier: ReturnType<typeof tokenVerifier>;
    expectedError: new (...args: any[]) => Error;
    expectedMessage: string;
    expectedCode?: string;
    expectedChallengeIncludes?: string[];
  }) {
    try {
      await verifier.verify();
      throw new Error('Expected verifier.verify() to throw, but it resolved');
    } catch (err) {
      // Note: We pass the error to `applyAuthChallenges` to ensure that DPoP challenge headers are added.
      // In production, this behavior is handled by the auth middleware, which catches the error and applies the challenges before returning it.
      const e = verifier.applyAuthChallenges(err) as AuthError;

      expect(e).toBeInstanceOf(expectedError);
      expect(e.message).toBe(expectedMessage);

      if (expectedCode) {
        expect(e.code).toBe(expectedCode);
      }

      const headers = e.headers;
      expect(headers).toBeDefined();
      expect(headers).toHaveProperty('WWW-Authenticate');

      const challenge = headers['WWW-Authenticate'];
      expect(typeof challenge).toBe('string');

      if (expectedChallengeIncludes?.length) {
        expect(challenge).toBe(expectedChallengeIncludes.join(', '));
      } else {
        expect(challenge).toBeUndefined();
      }
    }
  }

  const createVerifier = (
    jwtResult: VerifyJwtResult,
    options: AuthOptions = {},
    headers: Record<string, unknown> = {},
    query?: QueryLike,
    body?: BodyLike,
    isUrlEncoded = false
  ) => {
    const verifyJwtStub = sinon.stub().resolves(jwtResult);
    const verifier = tokenVerifier(verifyJwtStub, options, {
      ...baseRequest,
      headers,
      query,
      body,
      isUrlEncoded,
    });
    return { verifier, verifyJwtStub };
  };

  beforeEach(() => {
    if (!(dpopVerifier.verifyDPoP as any).restore) {
      sinon.spy(dpopVerifier, 'verifyDPoP'); // spy instead of stub
    }
  });

  afterEach(() => {
    sinon.restore();
  });

  it('"allowed" mode | verifies and calls `verifyDPoP` when `shouldVerifyDPoP` returns `true`', async () => {
    (dpopVerifier.verifyDPoP as sinon.SinonSpy).restore();
    sinon.stub(dpopVerifier, 'verifyDPoP').resolves();

    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc' } });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'DPoP ' + dummyJwt,
        dpop: 'some.dpop.jwt',
      }
    );

    const result = await verifier.verify();
    expect(result).toEqual(jwtResult);
    expect((dpopVerifier.verifyDPoP as sinon.SinonStub).calledOnce).toBe(true);
  });

  it('"allowed" mode | skips `verifyDPoP` when `shouldVerifyDPoP` returns `false`', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'Bearer ' + dummyJwt,
      }
    );

    const result = await verifier.verify();
    expect(result).toEqual(jwtResult);
    expect((dpopVerifier.verifyDPoP as sinon.SinonStub).notCalled).toBe(true);
  });

  it('"allowed" mode | throws if bearer scheme used but dpop header is present', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'Bearer ' + dummyJwt,
        dpop: 'some-proof',
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        'Bearer realm="api", error="invalid_request", error_description="Operation indicated DPoP use but the request\'s Authorization HTTP Header scheme is not DPoP"',
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `UnauthorizedError` if malformed `Bearer` Authorization header with valid DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'bearer ', // Malformed header (no token)
        dpop: 'proof.jwt',
      }
    );
    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [
        'Bearer realm="api"',
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidTokenError` if `Bearer` contains an invalid token', async () => {
    const verifyJwtStub = sinon.stub();
    verifyJwtStub.callsFake(async () => {
      throw new InvalidTokenError('signature verification failed');
    });

    const verifier = tokenVerifier(
      verifyJwtStub,
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: { authorization: 'Bearer invalid_token' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidTokenError,
      expectedMessage: 'signature verification failed',
      expectedCode: 'invalid_token',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_token", error_description="signature verification failed"`,
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidRequestError` if `Bearer` token is invalid and DPoP proof header is present', async () => {
    const verifyJwtStub = sinon.stub();
    verifyJwtStub.callsFake(async () => {
      throw new InvalidTokenError('signature verification failed');
    });

    const verifier = tokenVerifier(
      verifyJwtStub,
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'Bearer invalid_token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"`,
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidRequestError` if Bearer token is DPoP-bound but no DPoP proof header is present', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: {
        jkt: 'abc123',
      },
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Remove the stub to make it actually verify call `verifyDPoP`.

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'Bearer valid_dpop_bound_token',
          // Missing `dpop` proof header
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"`,
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidRequestError` if DPoP-bound token is used with DPoP scheme but no DPoP proof header is present', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: {
        jkt: 'abc123', // indicates DPoP-bound token
      },
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Remove the stub to make it actually verify call `verifyDPoP`.

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'DPoP valid_dpop_bound_token',
          // No `dpop` header
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request has no DPoP HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
        `Bearer realm="api"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidRequestError` if non-DPoP-bound token is used with DPoP scheme and a proof header is present', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      // no `cnf.jkt`, so NOT DPoP-bound
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Ensure real verifyDPoP is called

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'DPoP valid_non_bound_token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the JWT Access Token has no confirmation claim',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the JWT Access Token has no confirmation claim", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
        `Bearer realm="api"`,
      ],
    });
  });

  it('"allowed" mode | throws `UnauthorizedError` if request has DPoP proof header but no Authorization header', async () => {
    const verifier = tokenVerifier(
      sinon.stub().resolves(createJwtResult({ sub: 'user' })), // Won’t be called
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          dpop: 'valid.dpop.proof', // But no `authorization`
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: [
        `Bearer realm="api"`,
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `InvalidRequestError` if DPoP-bound token is in query param and DPoP proof header is missing', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: {
        jkt: 'abc123', // indicates DPoP-bound token
      },
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Ensure real verifyDPoP is called

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        query: {
          access_token: 'valid_dpop_bound_token',
        },
        headers: {
          // no Authorization, no DPoP header
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header"`,
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws `UnauthorizedError` if auth scheme is neither Bearer nor DPoP (with token in query)', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'random some_token',
        },
        query: {
          access_token: 'abc.def.ghi', // This is to cover a case where the token is in query param
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: [
        'Bearer realm="api"',
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"allowed" mode | throws if DPoP scheme is present but DPoP proof header is missing', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'DPoP ' + dummyJwt,
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request has no DPoP HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
        'Bearer realm="api"',
      ],
    });
  });

  it('"allowed" mode | throws UnauthorizedError if scheme is unknown', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true } },
      {
        authorization: 'MAC ' + dummyJwt,
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: [
        'Bearer realm="api"',
        `DPoP algs="${SUPPORTED_ALGS.join(' ')}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is Bearer with valid DPoP bound token and a valid DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        authorization: 'Bearer valid_dpop_bound_token',
        dpop: 'valid.dpop.proof',
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `UnauthorizedError` if authorization scheme is Bearer with an empty token and valid DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        authorization: 'Bearer ', // empty token would trigger UnauthorizedError
        dpop: 'valid.dpop.proof',
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: [`DPoP algs="${SUPPORTED_ALGS.join(' ')}"`],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is Bearer with an invalid Bearer token and no DPoP proof header', async () => {
    const badVerifyJwt = sinon
      .stub()
      .rejects(new InvalidTokenError('invalid bearer token')); // Simulate invalid token verification
    const verifier = tokenVerifier(
      badVerifyJwt,
      { dpop: { enabled: true, required: true } },
      { ...baseRequest, headers: { authorization: 'Bearer invalid' } } // Throws InvalidRequestError because no DPoP proof header is present
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is Bearer with an invalid Bearer token and valid DPoP proof header', async () => {
    const badVerifyJwt = sinon
      .stub()
      .rejects(new InvalidTokenError('invalid bearer token'));
    const verifier = tokenVerifier(
      badVerifyJwt,
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { authorization: 'Bearer invalid', dpop: 'proof.jwt' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP bound token and no DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { authorization: 'DPoP valid_dpop_bound_token' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request has no DPoP HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is Bearer with a valid Bearer token and no DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'Bearer ' + dummyJwt }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is Bearer with a valid DPoP bound token and no DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { authorization: 'Bearer valid_dpop_bound_token' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with an invalid DPoP bound token and no DPoP proof header', async () => {
    const badVerifyJwt = sinon
      .stub()
      .rejects(new InvalidTokenError('signature verification failed')); // Simulate invalid token verification
    const verifier = tokenVerifier(
      badVerifyJwt,
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { authorization: 'DPoP invalid_dpop_bound_token' },
        // No DPoP proof header: This will trigger `InvalidRequestError`
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request has no DPoP HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid Bearer(regular) token and a valid DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user' }); // no cnf.jkt => regular bearer token
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'DPoP valid_regular_bearer_token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the JWT Access Token has no confirmation claim',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the JWT Access Token has no confirmation claim", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP bound token and a malformed DPoP proof header', async () => {
    // Make verifyDPoP throw a predictable InvalidRequestError to avoid coupling to jose error text
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();
    sinon
      .stub(dpopVerifier, 'verifyDPoP')
      .rejects(new InvalidRequestError('Bad DPoP proof'));

    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { authorization: 'DPoP token', dpop: 'not-a-jws' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'Bad DPoP proof',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Bad DPoP proof", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `UnauthorizedError` if authorization scheme is a random string with a valid DPoP bound token and a valid DPoP proof header', async () => {
    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: {
          authorization: 'random token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`DPoP algs="${SUPPORTED_ALGS.join(' ')}"`],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization header is missing but DPoP proof header is present', async () => {
    // Put the token in query so we get to DPoP validation path (and then fail due to missing Authorization)
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc123' } },
      'query.dpop.bound'
    );
    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: true, required: true } },
      {
        ...baseRequest,
        headers: { dpop: 'valid.dpop.proof' }, // missing Authorization
        query: { access_token: 'query.dpop.bound' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | returns a valid result if authorization scheme is DPoP with a valid DPoP bound token and a valid DPoP proof header', async () => {
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();
    sinon.stub(dpopVerifier, 'verifyDPoP').resolves();

    const jwtResult = createJwtResult({ sub: 'user', cnf: { jkt: 'abc123' } });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {
        authorization: 'DPoP ' + dummyJwt,
        dpop: 'valid.dpop.proof',
      }
    );

    await expect(verifier.verify()).resolves.toEqual(jwtResult);
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP-bound token and also receives token via query', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP abc.def.ghi', dpop: 'proof.jwt' }, // token received via authentication header
      { access_token: 'abc.def.ghi' } // token received via query
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'More than one method used for authentication',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="More than one method used for authentication", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP-bound token and also receives token via query but doesn\'t contain DPoP proof', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP token-only' }, // headers (no dpop proof)
      { access_token: 'abc.def.ghi' } // query
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'More than one method used for authentication',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="More than one method used for authentication", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if missing Authorization header and receives a DPoP-bound token via query', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { dpop: 'valid.dpop.proof' }, // headers (no Authorization)
      { access_token: 'query.dpop.bound' } // query
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if missing Authorization and DPoP proof headers and receives a DPoP-bound token via query', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {}, // headers: neither Authorization nor DPoP
      { access_token: 'query.dpop.bound' } // query
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if RANDOM scheme contains a valid DPoP bound token and receives DPoP bound token via query as-well', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'RANDOM abc.def.hgi' }, // header source (unknown scheme)
      { access_token: 'abc.def.hgi' } // query source
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP-bound token and also receives token via body', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP abc.def.ghi', dpop: 'proof.jwt' }, // token received via authentication header
      {},
      { access_token: 'abc.def.ghi' }, // token received via body
      true // isUrlEncoded: true
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'More than one method used for authentication',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="More than one method used for authentication", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | succeeds when auth scheme is DPoP with a valid DPoP-bound token and a valid DPoP proof, even if a token is also present in body (isUrlEncoded: false)', async () => {
    // Make verifyDPoP succeed (we're not testing jose proof mechanics here)
    if ((dpopVerifier.verifyDPoP as any).restore) {
      (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();
    }
    sinon.stub(dpopVerifier, 'verifyDPoP').resolves();

    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'header.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP header.dpop.bound', dpop: 'proof.jwt' }, // valid DPoP scheme + proof
      undefined, // no query
      { access_token: 'body.token.ignored' }, // body token is ignored when isUrlEncoded === false
      false // isUrlEncoded: false
    );

    await expect(verifier.verify()).resolves.toEqual(jwtResult);
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP-bound token and also receives token via body but doesn\'t contain DPoP proof', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP token-only' }, // headers (no dpop proof)
      {},
      { access_token: 'abc.def.ghi' }, // body
      true // isUrlEncoded: true
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'More than one method used for authentication',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="More than one method used for authentication", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if authorization scheme is DPoP with a valid DPoP-bound token and also receives token via body but doesn\'t contain DPoP proof (isUrlEncoded: false)', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'DPoP token-only' }, // headers (no dpop proof)
      {},
      { access_token: 'abc.def.ghi' }, // body
      false // isUrlEncoded: false
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request has no DPoP HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if missing Authorization header and receives a DPoP-bound token via body', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { dpop: 'valid.dpop.proof' }, // headers (no Authorization)
      {},
      { access_token: 'query.dpop.bound' }, // body
      true // isUrlEncoded: true
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `UnauthorizedError` if missing Authorization header and receives a DPoP-bound token via body (isUrlEncoded: false)', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { dpop: 'valid.dpop.proof' }, // headers (no Authorization)
      {},
      { access_token: 'query.dpop.bound' }, // This access token will be ignored as isUrlEncoded is false
      false // isUrlEncoded: false
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`DPoP algs="${SUPPORTED_ALGS.join(' ')}"`],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if missing Authorization and DPoP proof headers and receives a DPoP-bound token via body', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {}, // headers: neither Authorization nor DPoP
      {},
      { access_token: 'query.dpop.bound' }, // body
      true // isUrlEncoded: true
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        'Operation indicated DPoP use but the request is missing an Authorization HTTP Header',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request is missing an Authorization HTTP Header", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `UnauthorizedError` if missing Authorization and DPoP proof headers and receives a DPoP-bound token via body (isUrlEncoded: false)', async () => {
    const jwtResult = createJwtResult(
      { sub: 'user', cnf: { jkt: 'abc' } },
      'query.dpop.bound'
    );

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      {}, // headers: NA
      {},
      { access_token: 'query.dpop.bound' }, // Token received via body will be ignored as `usUrlEncoded` is false
      false // isUrlEncoded: false
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`DPoP algs="${SUPPORTED_ALGS.join(' ')}"`],
    });
  });

  it('"required" mode | throws `InvalidRequestError` if RANDOM scheme contains a valid DPoP bound token and receives DPoP bound token via body as-well', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'RANDOM abc.def.hgi' }, // header source (unknown scheme)
      {},
      { access_token: 'abc.def.hgi' }, // body source
      true // isUrlEncoded: true
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage:
        "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP",
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `DPoP error="invalid_request", error_description="Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP", algs="${SUPPORTED_ALGS.join(
          ' '
        )}"`,
      ],
    });
  });

  it('"required" mode | throws `UnauthorizedError` if RANDOM scheme contains a valid DPoP bound token and receives DPoP bound token via body as-well (isUrlEncoded: false)', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: true, required: true } },
      { authorization: 'RANDOM abc.def.hgi' }, // header source (unknown scheme)
      {},
      { access_token: 'abc.def.hgi' }, // Token received via body will be ignored as `usUrlEncoded` is false
      false // isUrlEncoded: false
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`DPoP algs="${SUPPORTED_ALGS.join(' ')}"`],
    });
  });

  it('"disabled" mode | verifies successfully with Bearer token', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier, verifyJwtStub } = createVerifier(
      jwtResult,
      { dpop: { enabled: false } },
      { authorization: 'Bearer ' + dummyJwt }
    );

    const result = await verifier.verify();
    expect(result).toEqual(jwtResult);
    expect(verifyJwtStub.calledOnceWith(dummyJwt)).toBe(true);
    expect((dpopVerifier.verifyDPoP as sinon.SinonStub).notCalled).toBe(true);
  });

  it('"disabled" mode | throws if scheme is not bearer', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });
    const { verifier } = createVerifier(
      jwtResult,
      { dpop: { enabled: false } },
      { authorization: 'DPoP ' + dummyJwt }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: ['Bearer realm="api"'],
    });
  });

  it('"disabled" mode | throws `InvalidTokenError` if `Bearer` contains an invalid token | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const verifyJwtStub = sinon.stub();
    verifyJwtStub.callsFake(async () => {
      throw new InvalidTokenError('signature verification failed');
    });

    const verifier = tokenVerifier(
      verifyJwtStub,
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: { authorization: 'Bearer invalid_token' },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidTokenError,
      expectedMessage: 'signature verification failed',
      expectedCode: 'invalid_token',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_token", error_description="signature verification failed"`,
      ],
    });
  });

  it('"disabled" mode | throws `InvalidTokenError` if `Bearer` token is invalid and DPoP proof header is present | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const verifyJwtStub = sinon.stub();
    verifyJwtStub.callsFake(async () => {
      throw new InvalidTokenError('signature verification failed');
    });

    const verifier = tokenVerifier(
      verifyJwtStub,
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          authorization: 'Bearer invalid_token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidTokenError,
      expectedMessage: 'signature verification failed',
      expectedCode: 'invalid_token',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_token", error_description="signature verification failed"`,
      ],
    });
  });

  it('"disabled" mode | should not throw if DPoP-bound access token exists', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: { jkt: 'abc123' }, // token is DPoP-bound
    });

    // In disabled mode, DPoP is ignored. Keep the stub so verifyDPoP is NOT called.
    const verifyJwtStub = sinon.stub().resolves(jwtResult);

    const verifier = tokenVerifier(
      verifyJwtStub,
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          authorization: 'Bearer valid_dpop_bound_token',
          // No DPoP proof header on purpose
        },
      }
    );

    const result = await verifier.verify();

    expect(result).toEqual(jwtResult);
    expect(verifyJwtStub.calledOnceWith('valid_dpop_bound_token')).toBe(true);
    expect((dpopVerifier.verifyDPoP as sinon.SinonStub).notCalled).toBe(true);
  });

  it('"disabled" mode | throws `UnauthorizedError` if DPoP-bound token is used with DPoP scheme | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: {
        jkt: 'abc123', // indicates DPoP-bound token
      },
    });

    // Remove the stub to make it actually verify call `verifyDPoP`.
    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore();

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          authorization: 'DPoP valid_dpop_bound_token',
          // No `dpop` header
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`Bearer realm="api"`],
    });
  });

  it('"disabled" mode | throws `UnauthorizedError` if `Bearer` token is used with DPoP scheme and a proof header is present | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      // no `cnf.jkt`, so NOT DPoP-bound
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Ensure real verifyDPoP is called

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          authorization: 'DPoP valid_non_bound_token',
          dpop: 'valid.dpop.proof',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedCode: undefined,
      expectedChallengeIncludes: [`Bearer realm="api"`],
    });
  });

  it('"disabled" mode | throws `UnauthorizedError` if request has no auth header, and token was not sent via query or body | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const verifier = tokenVerifier(
      sinon.stub().resolves(createJwtResult({ sub: 'user' })), // Won’t be called
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          dpop: 'valid.dpop.proof', // But no `authorization`
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: [`Bearer realm="api"`],
    });
  });

  it('"disabled" mode | throws `InvalidRequestError` if `Bearer` token is in query param and in authentication header (Multiple location) | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const jwtResult = createJwtResult({
      sub: 'user',
      cnf: {
        jkt: 'abc123', // indicates DPoP-bound token
      },
    });

    (dpopVerifier.verifyDPoP as sinon.SinonStub).restore(); // Ensure real verifyDPoP is called

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        query: {
          access_token: 'valid_dpop_bound_token',
        },
        headers: {
          authorization: 'Bearer valid_bearer_token', // Added Authorization header
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: InvalidRequestError,
      expectedMessage: 'More than one method used for authentication',
      expectedCode: 'invalid_request',
      expectedChallengeIncludes: [
        `Bearer realm="api", error="invalid_request", error_description="More than one method used for authentication"`,
      ],
    });
  });

  it('"disabled" mode | throws `UnauthorizedError` if auth scheme is `random` but the token is also received via query | `WWW-Authenticate` would contain only `Bearer` challenge', async () => {
    const jwtResult = createJwtResult({ sub: 'user' });

    const verifier = tokenVerifier(
      sinon.stub().resolves(jwtResult),
      { dpop: { enabled: false } },
      {
        ...baseRequest,
        headers: {
          authorization: 'random some_token',
        },
        query: {
          access_token: 'abc.def.ghi',
        },
      }
    );

    await expectVerifyToThrow({
      verifier,
      expectedError: UnauthorizedError,
      expectedMessage: 'Unauthorized',
      expectedChallengeIncludes: ['Bearer realm="api"'],
    });
  });
});
