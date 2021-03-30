/**
 * Errors per https://tools.ietf.org/html/rfc6750#section-3.1
 */

/**
 * If the request lacks any authentication information,
 * the resource server SHOULD NOT include an error code or
 * other error information.
 */
export class UnauthorizedError extends Error {
  message = 'Unauthorized';
  status = 401;
  statusCode = 401;
  headers = { 'www-authentication': 'Bearer realm="api"' };

  constructor() {
    super();
    this.name = this.constructor.name;
  }
}

/**
 * The request is missing a required parameter, includes an
 * unsupported parameter or parameter value, repeats the same
 * parameter, uses more than one method for including an access
 * token, or is otherwise malformed.
 */
export class InvalidRequestError extends UnauthorizedError {
  code = 'invalid_request';
  message = 'Invalid Request';
  status = 400;
  statusCode = 400;

  constructor() {
    super();
    this.headers = getHeaders(this.code, this.message);
  }
}

/**
 * The access token provided is expired, revoked, malformed, or
 * invalid for other reasons.
 */
export class InvalidTokenError extends UnauthorizedError {
  code = 'invalid_token';
  message = 'Invalid Token';
  status = 401;
  statusCode = 401;

  constructor() {
    super();
    this.headers = getHeaders(this.code, this.message);
  }
}

/**
 * The request requires higher privileges than provided by the
 * access token.
 */
export class InsufficientScopeError extends UnauthorizedError {
  code = 'insufficient_scope';
  message = 'Insufficient Scope';
  status = 403;
  statusCode = 403;

  constructor(scopes?: string[]) {
    super();
    this.headers = getHeaders(this.code, this.message, scopes);
  }
}

/**
 * Generate a response header per https://tools.ietf.org/html/rfc6750#section-3
 */
const getHeaders = (error: string, description: string, scopes?: string[]) => ({
  'www-authentication': `Bearer realm="api", error="${error}", error_description="${description}"${
    (scopes && `, scope="${scopes.join(' ')}"`) || ''
  }`,
});
