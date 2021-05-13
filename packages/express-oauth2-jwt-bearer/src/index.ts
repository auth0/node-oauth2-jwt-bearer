import { Handler, NextFunction, Request, Response } from 'express';
import {
  jwtVerifier,
  WithDiscovery,
  WithoutDiscovery,
  claimCheck as _claimCheck,
  ClaimCheck,
  claimEquals as _claimEquals,
  ClaimEquals,
  claimIncludes as _claimIncludes,
  ClaimIncludes,
  requiredScopes as _requiredScopes,
  RequiredScopes,
  VerifyJwtResult,
  JWTPayload,
} from 'access-token-jwt';
import { getToken } from 'oauth2-bearer';

declare global {
  namespace Express {
    interface Request {
      auth?: VerifyJwtResult;
    }
  }
}

/**
 * @ignore
 */
export interface Auth {
  (opts: WithDiscovery): Handler;
  (opts: WithoutDiscovery): Handler;
}

/**
 * Middleware that will return a 401 if a valid JWT bearer token is not provided
 * in the request.
 *
 * Can be used in 2 ways, {@Link WithDiscovery}:
 *
 * ```js
 * app.use({
 *   issuerBaseURL: 'http://issuer.example.com',
 *   audience: 'https://myapi.com'
 * });
 * ```
 *
 * This uses the {@Link issuerBaseURL} to find the OAuth 2.0 Authorization
 * Server Metadata to get the {@Link jwksUri} and {@issuer}.
 *
 * You can also skip discovery and pass in options that match
 * {@Link WithoutDiscovery}. By providing {@Link jwksUri} and {@issuer}
 * yourself.
 *
 * ```js
 * app.use({
 *   jwksUri: 'http://issuer.example.com/well-known/jwks.json',
 *   issuer: 'http://issuer.example.com',
 *   audience: 'https://myapi.com'
 * });
 * ```
 *
 */
export const auth: Auth = (opts: any): Handler => {
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
      next(e);
    }
  };
};

const toHandler = (fn: (payload?: JWTPayload) => void): Handler => (
  req,
  res,
  next
) => {
  try {
    fn(req.auth?.payload);
    next();
  } catch (e) {
    next(e);
  }
};

export const claimCheck: ClaimCheck<Handler> = (...args) =>
  toHandler(_claimCheck(...args));

export const claimEquals: ClaimEquals<Handler> = (...args) =>
  toHandler(_claimEquals(...args));

export const claimIncludes: ClaimIncludes<Handler> = (...args) =>
  toHandler(_claimIncludes(...args));

export const requiredScopes: RequiredScopes<Handler> = (...args) =>
  toHandler(_requiredScopes(...args));

export { WithDiscovery, WithoutDiscovery, JWTPayload };
export {
  FunctionValidator,
  Validator,
  Validators,
  JWTHeader,
} from 'access-token-jwt';
