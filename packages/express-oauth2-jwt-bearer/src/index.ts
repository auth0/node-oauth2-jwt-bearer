import { Handler, NextFunction, Request, Response } from 'express';
import {
  jwtVerifier,
  JwtVerifierOptions,
  claimCheck as _claimCheck,
  ClaimCheck,
  claimEquals as _claimEquals,
  ClaimEquals,
  claimIncludes as _claimIncludes,
  ClaimIncludes,
  requiredScopes as _requiredScopes,
  RequiredScopes,
  scopeIncludesAny as _scopeIncludesAny,
  VerifyJwtResult as AuthResult,
} from 'access-token-jwt';
import type { JWTPayload } from 'access-token-jwt';
import { getToken } from 'oauth2-bearer';

export interface AuthOptions extends JwtVerifierOptions {
  /**
   * True if a valid Access Token JWT should be required for all routes.
   * Defaults to true.
   */
  authRequired?: boolean;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthResult;
    }
  }
}

/**
 * Middleware that will return a 401 if a valid JWT bearer token is not provided
 * in the request.
 *
 * Can be used in 2 ways:
 *
 * 1. Pass in an {@Link AuthOptions.issuerBaseURL} (or define the env
 * variable `ISSUER_BASE_URL`)
 *
 * ```js
 * app.use(auth({
 *   issuerBaseURL: 'http://issuer.example.com',
 *   audience: 'https://myapi.com'
 * }));
 * ```
 *
 * This uses the {@Link AuthOptions.issuerBaseURL} to find the OAuth 2.0
 * Authorization Server Metadata to get the {@Link AuthOptions.jwksUri}
 * and {@Link AuthOptions.issuer}.
 *
 * 2. You can also skip discovery and provide the {@Link AuthOptions.jwksUri} (or
 * define the env variable `JWKS_URI`) and {@Link AuthOptions.issuer} (or define
 * the env variable `ISSUER`) yourself.
 *
 * ```js
 * app.use(auth({
 *   jwksUri: 'http://issuer.example.com/well-known/jwks.json',
 *   issuer: 'http://issuer.example.com',
 *   audience: 'https://myapi.com'
 * }));
 * ```
 *
 * You must provide the `audience` argument (or `AUDIENCE` environment variable)
 * used to match against the Access Token's `aud` claim.
 *
 * Successful requests will have the following properties added to them:
 *
 * ```js
 * app.get('/foo', auth(), (req, res, next) => {
 *   const auth = req.auth;
 *   auth.header; // The decoded JWT header.
 *   auth.payload; // The decoded JWT payload.
 *   auth.token; // The raw JWT token.
 * });
 * ```
 *
 */
export const auth = (opts: AuthOptions = {}): Handler => {
  const verifyJwt = jwtVerifier(opts);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const jwt = getToken(
        req.headers,
        req.query,
        req.body,
        !!req.is('urlencoded')
      );
      req.auth = await verifyJwt(jwt);
      next();
    } catch (e) {
      if (opts.authRequired === false) {
        next();
      } else {
        next(e);
      }
    }
  };
};

const toHandler =
  (fn: (payload?: JWTPayload) => void): Handler =>
  (req, res, next) => {
    try {
      fn(req.auth?.payload);
      next();
    } catch (e) {
      next(e);
    }
  };

/**
 * Check the token's claims using a custom method that receives the
 * {@Link JWTPayload} and should return `true` if the token is valid. Raises
 * a 401 `invalid_token` error if the function returns false. You can also
 * customise the `error_description` which should be formatted per rfc6750.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin/edit', claimCheck((claims) => {
 *   return claims.isAdmin && claims.roles.includes('editor');
 * }, `Unexpected 'isAdmin' and 'roles' claims`), (req, res) => { ... });
 * ```
 */
export const claimCheck: ClaimCheck<Handler> = (...args) =>
  toHandler(_claimCheck(...args));

/**
 * Check a token's claim to be equal a given {@Link JSONPrimitive}
 * (`string`, `number`, `boolean` or `null`) raises a 401 `invalid_token`
 * error if the value of the claim does not match.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin', claimEquals('isAdmin', true), (req, res) => { ... });
 * ```
 */
export const claimEquals: ClaimEquals<Handler> = (...args) =>
  toHandler(_claimEquals(...args));

/**
 * Check a token's claim to include a number of given {@Link JSONPrimitive}s
 * (`string`, `number`, `boolean` or `null`) raises a 401 `invalid_token`
 * error if the value of the claim does not include all the given values.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin/edit', claimIncludes('role', 'admin', 'editor'),
 *    (req, res) => { ... });
 * ```
 */
export const claimIncludes: ClaimIncludes<Handler> = (...args) =>
  toHandler(_claimIncludes(...args));

/**
 * Check a token's `scope` claim to include a number of given scopes, raises a
 * 403 `insufficient_scope` error if the value of the `scope` claim does not
 * include all the given scopes.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin/edit', requiredScopes('read:admin write:admin'),
 *    (req, res) => { ... });
 * ```
 */
export const requiredScopes: RequiredScopes<Handler> = (...args) =>
  toHandler(_requiredScopes(...args));

/**
 * Check a token's `scope` claim to include any of the given scopes, raises a
 * 403 `insufficient_scope` error if the value of the `scope` claim does not
 * include any of the given scopes.
 *
 * ```js
 * app.use(auth());
 *
 * app.get('/admin/edit', scopeIncludesAny('read:msg read:admin'),
 *    (req, res) => { ... });
 * ```
 */
export const scopeIncludesAny: RequiredScopes<Handler> = (...args) =>
  toHandler(_scopeIncludesAny(...args));

export { AuthResult, JWTPayload };
export {
  FunctionValidator,
  Validator,
  Validators,
  JWTHeader,
  JSONPrimitive,
} from 'access-token-jwt';
export {
  UnauthorizedError,
  InvalidRequestError,
  InvalidTokenError,
  InsufficientScopeError,
} from 'oauth2-bearer';
