import {
  UnauthorizedError,
  InvalidRequestError,
  InvalidTokenError,
  InsufficientScopeError,
} from '../src/errors';

describe('errors', () => {
  it('should raise an Unauthorized error', () => {
    expect(new UnauthorizedError()).toMatchObject({
      headers: {
        'www-authentication': 'Bearer realm="api"',
      },
      message: 'Unauthorized',
      name: 'UnauthorizedError',
      status: 401,
      statusCode: 401,
    });
  });

  it('should raise an Invalid Request error', () => {
    expect(new InvalidRequestError()).toMatchObject({
      code: 'invalid_request',
      headers: {
        'www-authentication':
          'Bearer realm="api", error="invalid_request", error_description="Invalid Request"',
      },
      message: 'Invalid Request',
      name: 'InvalidRequestError',
      status: 400,
      statusCode: 400,
    });
  });

  it('should raise an Invalid Token error', () => {
    expect(new InvalidTokenError()).toMatchObject({
      code: 'invalid_token',
      headers: {
        'www-authentication':
          'Bearer realm="api", error="invalid_token", error_description="Invalid Token"',
      },
      message: 'Invalid Token',
      name: 'InvalidTokenError',
      status: 401,
      statusCode: 401,
    });
  });

  it('should raise an Insufficient Scope error', () => {
    expect(new InsufficientScopeError(['foo', 'bar'])).toMatchObject({
      code: 'insufficient_scope',
      headers: {
        'www-authentication':
          'Bearer realm="api", error="insufficient_scope", error_description="Insufficient Scope", scope="foo bar"',
      },
      message: 'Insufficient Scope',
      name: 'InsufficientScopeError',
      status: 403,
      statusCode: 403,
    });
  });
});
