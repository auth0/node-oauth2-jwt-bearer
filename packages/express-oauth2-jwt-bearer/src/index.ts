import { Handler, NextFunction, Request, Response } from 'express';
import { Request as ExpressRequest } from 'express';
import {
  jwtVerifier,
  tokenVerifier,
  assertValidDPoPOptions,
  assertValidMtlsOptions,
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
  JWTPayload,
  RequestLike,
  AuthOptions as CoreAuthOptions,
  DPoPOptions,
  MtlsOptions,
  ClientCertificate
} from 'access-token-jwt';
import { resolveHost } from './resolve-host';

/**
 * Resolves the client certificate presented on the TLS connection for the
 * current request, used to validate certificate-bound (mTLS, RFC 8705) access
 * tokens.
 *
 * APIs typically run behind a TLS-terminating proxy (nginx, ALB, Cloudflare,
 * etc.) that forwards the client certificate in a request header (commonly as
 * URL-encoded PEM). Because the header name and encoding vary by deployment,
 * you supply this function to extract the certificate from wherever your proxy
 * places it, returning the PEM text or DER bytes. For a process terminating TLS
 * directly, return `req.socket.getPeerCertificate().raw`.
 *
 * Return `undefined` when no certificate is present; a certificate-bound token
 * received without one is rejected.
 *
 * @example
 * // nginx forwarding URL-encoded PEM in a header:
 * getCertificate: (req) => {
 *   const pem = req.headers['client-certificate'];
 *   return typeof pem === 'string' ? decodeURIComponent(pem) : undefined;
 * }
 */
export type GetCertificate = (
  req: ExpressRequest
) => ClientCertificate | undefined;

export type AuthOptions = CoreAuthOptions & {
  /**
   * Resolves the client certificate for mTLS certificate-bound access token
   * validation (RFC 8705). Required to validate `cnf.x5t#S256` bindings when
   * running behind a TLS-terminating proxy.
   */
  getCertificate?: GetCertificate;
};

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
  assertValidDPoPOptions(opts.dpop);
  assertValidMtlsOptions(opts.mtls);

  return async (req: Request, res: Response, next: NextFunction) => {
    const { headers, query, body, method } = req;

    // Construct the URL from the request object. resolveHost validates the
    // untrusted Host header and throws InvalidRequestError on a malformed value,
    // so this runs before any verifier is constructed.
    let url: string;
    try {
      url = `${req.protocol}://${resolveHost(req)}${req.originalUrl ?? req.url}`;
    } catch (e) {
      if (opts.authRequired === false) {
        return next();
      }
      return next(e);
    }

    // Resolve the client certificate for mTLS certificate-bound tokens, if a
    // resolver was supplied. Errors from the caller's resolver propagate through
    // the same authRequired handling as other verification failures.
    let clientCertificate: ClientCertificate | undefined;
    try {
      clientCertificate = opts.getCertificate?.(req);
    } catch (e) {
      if (opts.authRequired === false) {
        return next();
      }
      return next(e);
    }

    // Get DPoP verifier instance with the provided options.
    const requestOptions: RequestLike = {
      headers,
      url,
      method,
      query,
      body,
      isUrlEncoded: !!req.is('urlencoded'),
      clientCertificate,
    };

    // Verify both JWT and DPoP token claims.
    const verifier = tokenVerifier(verifyJwt, opts, requestOptions);

    try {
      req.auth = await verifier.verify();
      next();
    } catch (e) {
      if (opts.authRequired === false) {
        next();
      } else {
        // Apply authentication challenges to the response if the request is a DPoP request.
        next(verifier.applyAuthChallenges(e));
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

export {
  AuthResult,
  JWTPayload,
  DPoPOptions,
  MtlsOptions,
  ClientCertificate,
};
export {
  FunctionValidator,
  Validator,
  Validators,
  JWTHeader,
  JSONPrimitive,
  PublicKeyInput,
  MCDOptions,
  AsymmetricIssuerConfig,
  SymmetricIssuerConfig,
  IssuerConfig,
  IssuerResolverContext,
  IssuerResolverResult,
  IssuerResolverFunction,
  RequestContext,
} from 'access-token-jwt';
export {
  UnauthorizedError,
  InvalidRequestError,
  InvalidTokenError,
  InsufficientScopeError,
} from 'oauth2-bearer';
