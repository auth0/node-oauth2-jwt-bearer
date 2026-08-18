import {
  InvalidRequestError,
  InvalidTokenError,
  UnauthorizedError,
} from 'oauth2-bearer';
import { strict as assert } from 'assert';

import type {
  VerifyJwt,
  JwtVerifierOptions,
  VerifyJwtResult,
} from './jwt-verifier';

import { ASYMMETRIC_ALGS as SUPPORTED_ALGORITHMS } from './jwt-verifier';

import {
  isJsonObject,
  normalizeUrl,
  verifyDPoP,
  assertDPoPRequest,
  DPoPJWTPayload,
} from './dpop-verifier';

import { verifyMtls, ClientCertificate } from './mtls-verifier';

const DEFAULT_DPOP_ENABLED = true; // DPoP is enabled by default.
const DEFAULT_DPOP_REQUIRED = false; // DPoP is allowed by default.
const DEFAULT_IAT_OFFSET = 300; // 5 minutes.
const DEFAULT_IAT_LEEWAY = 30; // 30 seconds.
const DEFAULT_MTLS_ENABLED = false; // mTLS is opt-in: cnf.x5t#S256 is ignored unless enabled.
const DEFAULT_MTLS_REQUIRED = false; // Certificate-bound tokens are allowed, not required.

/**
 * Returns true if the access token is DPoP-bound (carries a `cnf.jkt` claim).
 */
function isDPoPBound(accessTokenClaims: DPoPJWTPayload): boolean {
  return (
    isJsonObject(accessTokenClaims.cnf) && 'jkt' in accessTokenClaims.cnf!
  );
}

/**
 * Returns true if the access token is certificate-bound per RFC 8705
 * (carries a `cnf.x5t#S256` claim).
 */
function isMtlsBound(accessTokenClaims: DPoPJWTPayload): boolean {
  return (
    isJsonObject(accessTokenClaims.cnf) && 'x5t#S256' in accessTokenClaims.cnf!
  );
}

/**
 * Options that control Demonstration of Proof-of-Possession (DPoP) handling.
 *
 * @remarks
 * DPoP (RFC 9449) is an application-level mechanism to sender-constrain OAuth 2.0
 * access/refresh tokens by proving possession of a private key. This SDK supports
 * validating DPoP proofs on incoming requests when enabled.
 *
 * Behavior matrix:
 *
- <u>Default</u> (*`{ enabled: true, required: false }`*):  
  Accepts both Bearer and DPoP, validating the DPoP proof when present.

- <u>Bearer-only</u> (*`{ enabled: false, required: false }`*):  
  Rejects any non-Bearer scheme tokens (including those using the DPoP scheme), accepts DPoP-bound tokens over Bearer (ignoring `cnf`), and ignores any DPoP proof headers if present.

- <u>Misconfiguration</u> (*`{ enabled: false, required: true }`*):  
  This configuration is invalid. DPoP is disabled, and the SDK cannot be used with this setting.

- <u>DPoP-only</u> (*`{ enabled: true, required: true }`*):  
  Accepts only tokens using the DPoP scheme, validates the associated DPoP proof, and rejects any token using a different (non-DPoP) scheme.

 *
 * Proof timing:
 * - `iatOffset` bounds how far in the past a proof’s `iat` may be (replay window).
 * - `iatLeeway` allows limited clock skew for proofs that appear slightly in the future.
 *
 * Note:
 * This SDK uses `req.protocol` and `req.host` to construct/validate the DPoP `htu`.
 * If your app runs behind a reverse proxy (Nginx, Cloudflare, etc.), enable Express
 * proxy trust to ensure correct values:
 *
 * ```js
 * app.enable('trust proxy');
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc9449
 */
interface DPoPOptions {
  /**
   * Enables DPoP support.
   *
   * When `enabled: true`:
   * - Requests can use the DPoP authorization scheme (`Authorization: DPoP …` plus a `DPoP` proof header), and the middleware will validate proofs.
   *
   * When `enabled: false`:
   * - Only the Bearer scheme is supported.
   * - Any token sent with the DPoP scheme is rejected.
   * - DPoP-bound tokens sent with Bearer are accepted (the `cnf` claim is ignored).
   * - Any `DPoP` proof header is ignored.
   *
   * @default true
   * @example
   * // Accept both Bearer and DPoP (default):
   * auth({ dpop: { enabled: true, required: false } })
   *
   * @example
   * // Bearer-only (DPoP disabled):
   * auth({ dpop: { enabled: false } })
   */
  enabled?: boolean;

  /**
   * Requires DPoP tokens exclusively when DPoP is enabled.
   *
   * When `enabled: true` and `required: true`:
   * - Only DPoP tokens are accepted, and non-DPoP tokens are rejected.
   *
   * When `enabled: false`:
   * - Setting this flag results in a misconfiguration (Bearer-only mode).
   *
   * @default false
   * @example
   * // DPoP-only:
   * auth({ dpop: { enabled: true, required: true } })
   */
  required?: boolean;

  /**
   * Maximum accepted age (in seconds) for a DPoP proof’s `iat` claim.
   *
   * Proofs older than `iatOffset` (relative to current server time) are rejected.
   * This is applied only when `enabled: true` and a DPoP proof is present.
   *
   * @default 300  // 5 minutes
   * @example
   * // Reject proofs older than 2 minutes
   * auth({ dpop: { enabled: true, iatOffset: 120 } })
   */
  iatOffset?: number;

  /**
   * Allowed clock skew (in seconds) for future-dated `iat` values.
   *
   * Some clients have slightly skewed clocks; a small positive leeway prevents valid proofs
   * from being rejected when `iat` appears a bit in the future.
   * This is applied only when `enabled: true` and a DPoP proof is present.
   *
   * @default 30  // 30 seconds
   * @example
   * // Allow up to 60 seconds of client/server clock skew
   * auth({ dpop: { enabled: true, iatLeeway: 60 } })
   */
  iatLeeway?: number;
}

/**
 * Options that control mutual-TLS certificate-bound access token validation
 * (RFC 8705 §3).
 *
 * @remarks
 * When a client authenticates to the authorization server with a TLS client
 * certificate, the issued access token carries a `cnf.x5t#S256` claim: the
 * base64url-encoded SHA-256 thumbprint of that certificate. This SDK validates,
 * on each request, that the certificate presented on the TLS connection matches
 * the thumbprint in the token.
 *
 * Because APIs commonly run behind a TLS-terminating proxy (nginx, ALB,
 * Cloudflare, etc.), the SDK cannot read the TLS socket directly. The client
 * certificate must be supplied by the caller — see `getCertificate` on the
 * Express `auth()` middleware — and is then passed to this verifier as raw
 * PEM or DER.
 *
 * mTLS is opt-in: unlike DPoP, it depends on a certificate resolver the
 * caller must supply (see `getCertificate` on the Express `auth()`
 * middleware), so it cannot safely default to on. The Express middleware
 * enables it automatically when `getCertificate` is supplied, unless
 * `enabled` is set explicitly.
 *
 * Behavior matrix:
 *
 * - <u>Default</u> (*`{ enabled: false }`*):
 *   The `cnf.x5t#S256` claim is ignored and no certificate binding is checked.
 *
 * - <u>Enabled</u> (*`{ enabled: true, required: false }`*):
 *   Validates the certificate binding when the token carries `cnf.x5t#S256`;
 *   plain bearer tokens are accepted as-is.
 *
 * - <u>Required</u> (*`{ enabled: true, required: true }`*):
 *   Every access token must be certificate-bound; a token without a valid
 *   `cnf.x5t#S256` binding is rejected.
 *
 * - <u>Misconfiguration</u> (*`{ required: true }`* without *`enabled: true`*):
 *   Invalid — a binding cannot be required unless mTLS is explicitly enabled.
 *
 * Interaction with DPoP:
 * A token carries at most one confirmation method, so mTLS and DPoP are mutually
 * exclusive per token. When both are enabled, DPoP is evaluated first and takes
 * precedence: the mTLS verifier runs only for requests the DPoP path does not
 * handle. As a result `required: true` is scoped to the mTLS path (it does not
 * force a certificate binding on a request satisfied by a DPoP-bound token), and
 * enabling `dpop.required` makes these options inert because every request is
 * then routed to the DPoP path.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8705
 */
interface MtlsOptions {
  /**
   * Enables validation of certificate-bound (`cnf.x5t#S256`) access tokens.
   *
   * mTLS is opt-in. The Express `auth()` middleware sets this to `true`
   * automatically when a `getCertificate` resolver is supplied, unless you
   * set it explicitly.
   *
   * @default false
   */
  enabled?: boolean;

  /**
   * Requires every access token to be certificate-bound. When `true`, a token
   * without a valid `cnf.x5t#S256` binding is rejected.
   *
   * Scoped to the mTLS path: when DPoP is also enabled, DPoP is evaluated first,
   * so a DPoP-bound token is handled by the DPoP path and this requirement is
   * not applied to it.
   *
   * Requires `enabled: true` to also be set explicitly; mTLS being opt-in
   * means it cannot be turned on implicitly just by requiring it.
   *
   * @default false
   */
  required?: boolean;
}

interface AuthOptions extends JwtVerifierOptions {
  /**
   * True if a valid Access Token JWT should be required for all routes.
   * Defaults to true.
   */
  authRequired?: boolean;

  /**
   * Options to configure DPoP (Demonstration of Proof of Possession) validation.
   * If not provided or set to `undefined`, the following default values will be used:
   * {
   *   enabled: true,
   *   required: false,
   *   iatOffset: 300, // 5 minutes
   *   iatLeeway: 30, // 30 seconds
   * }
   */
  dpop?: DPoPOptions;

  /**
   * Options to configure mTLS certificate-bound access token validation
   * (RFC 8705). If not provided or set to `undefined`, the following default
   * values will be used:
   * {
   *   enabled: false,
   *   required: false,
   * }
   *
   * mTLS is opt-in: the Express `auth()` middleware sets `enabled: true`
   * automatically when a `getCertificate` resolver is supplied, unless you
   * set `enabled` explicitly.
   */
  mtls?: MtlsOptions;
}
export interface AuthError extends UnauthorizedError {
  code?: string;
}

type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  dpop?: string;
};

type QueryLike = Record<string, unknown> & { access_token?: string };
type BodyLike = QueryLike;

type TokenInfo = {
  location: 'header' | 'query' | 'body';
  jwt: string;
};

type RequestLike = Record<string, unknown> & {
  headers: HeadersLike;
  url: string;
  method: string;
  query?: QueryLike;
  body?: BodyLike;
  isUrlEncoded?: boolean; // true if the request's Content-Type is `application/x-www-form-urlencoded`
  clientCertificate?: ClientCertificate; // the client certificate presented on the TLS connection, resolved by the caller (mTLS, RFC 8705)
};

// Normalize headers to a lowercase key object
function normalizeHeaders(input: unknown): HeadersLike {
  if (!isJsonObject(input)) {
    return {};
  }

  const headers: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (typeof k === 'string') {
      headers[k.toLowerCase()] = v;
    }
  }

  return headers;
}

/**
 * Extracts the authorization scheme from the request headers.
 * Throws InvalidRequestError if the format is invalid.
 *
 * @method getAuthScheme
 * @param headers - The request headers containing the Authorization field
 * @returns The authorization scheme (e.g., 'dpop', 'bearer') or undefined if not present
 * */
function getAuthScheme(headers: HeadersLike): string | undefined {
  const authorization = headers.authorization;
  if (typeof authorization === 'string') {
    const parts = authorization.split(' ');
    if (parts.length === 2) {
      return parts[0].toLowerCase();
    }
  }

  return undefined;
}

/**
 * Asserts that the provided DPoP options are valid.
 * Throws an error if any of the options are invalid.
 *
 * @param dpopOptions - The DPoP options to validate
 * @throws {Error} If the options are invalid
 */
function assertValidDPoPOptions(dpopOptions?: DPoPOptions): void {
  if (dpopOptions === undefined) return;

  assert(
    isJsonObject(dpopOptions),
    'Invalid DPoP configuration: "dpop" must be an object'
  );

  const { enabled, required, iatOffset, iatLeeway } = dpopOptions;

  if (enabled !== undefined) {
    assert(
      typeof enabled === 'boolean',
      'Invalid DPoP option: "enabled" must be a boolean'
    );
  }

  if (required !== undefined) {
    assert(
      typeof required === 'boolean',
      'Invalid DPoP option: "required" must be a boolean'
    );
  }

  if (iatOffset !== undefined) {
    assert(
      typeof iatOffset === 'number',
      'Invalid DPoP option: "iatOffset" must be a number'
    );

    assert(
      iatOffset >= 0,
      'Invalid DPoP option: "iatOffset" must be a non-negative number'
    );
  }

  if (iatLeeway !== undefined) {
    assert(
      typeof iatLeeway === 'number',
      'Invalid DPoP option: "iatLeeway" must be a number'
    );

    assert(
      iatLeeway >= 0,
      'Invalid DPoP option: "iatLeeway" must be a non-negative number'
    );
  }

  assert(
    !(enabled === false && required === true),
    'Invalid DPoP configuration: cannot set "required" to true when "enabled" is false'
  );
}

/**
 * Asserts that the provided mTLS options are valid.
 * Throws an error if any of the options are invalid.
 *
 * @param mtlsOptions - The mTLS options to validate
 * @throws {Error} If the options are invalid
 */
function assertValidMtlsOptions(mtlsOptions?: MtlsOptions): void {
  if (mtlsOptions === undefined) return;

  assert(
    isJsonObject(mtlsOptions),
    'Invalid mTLS configuration: "mtls" must be an object'
  );

  const { enabled, required } = mtlsOptions;

  if (enabled !== undefined) {
    assert(
      typeof enabled === 'boolean',
      'Invalid mTLS option: "enabled" must be a boolean'
    );
  }

  if (required !== undefined) {
    assert(
      typeof required === 'boolean',
      'Invalid mTLS option: "required" must be a boolean'
    );
  }

  assert(
    !(required === true && enabled !== true),
    'Invalid mTLS configuration: "required" can only be set to true when "enabled" is also true'
  );
}

function tokenVerifier(
  verifyJwt: VerifyJwt,
  options: AuthOptions = {},
  requestOptions: RequestLike
) {
  // Extract headers, url, and method from requestOptions
  const headers = normalizeHeaders(requestOptions?.headers || {});
  const method = requestOptions?.method;
  const query = requestOptions?.query;
  const body = requestOptions?.body;
  const isUrlEncoded = requestOptions?.isUrlEncoded ?? false;
  const clientCertificate = requestOptions?.clientCertificate;
  const authScheme = getAuthScheme(headers)?.toLowerCase();
  // Extract DPoP options from the provided options or use defaults
  const {
    dpop: {
      enabled: dpopEnabled = DEFAULT_DPOP_ENABLED,
      required: dpopRequired = DEFAULT_DPOP_REQUIRED,
      iatOffset = DEFAULT_IAT_OFFSET,
      iatLeeway = DEFAULT_IAT_LEEWAY,
    } = {},
    mtls: {
      enabled: mtlsEnabled = DEFAULT_MTLS_ENABLED,
      required: mtlsRequired = DEFAULT_MTLS_REQUIRED,
    } = {},
  } = options;
  let hasNonHeaderToken = false;
  let url = requestOptions?.url;


  /**
   * Determines whether DPoP validation is required for a given request context.
   *
   * Validation is triggered if:
   * - DPoP is enabled, AND (
   *   - DPoP is required by configuration
   *   - OR the Authorization scheme is 'DPoP'
   *   - OR the token contains a `cnf.jkt` claim (token is bound)
   *   - OR the request contains a DPoP header
   * )
   *
   * @method shouldVerifyDPoP
   * @param options - Validation context
   * @returns `true` if DPoP validation should be enforced
   */
  function shouldVerifyDPoP(accessTokenClaims: DPoPJWTPayload): boolean {
    if (!dpopEnabled) {
      return false;
    }

    const hasDPoPHeader = 'dpop' in headers;
    const isDPoPScheme = authScheme === 'dpop';
    const hasBoundToken = isDPoPBound(accessTokenClaims);

    return dpopRequired || isDPoPScheme || hasBoundToken || hasDPoPHeader;
  }

  /**
   * Determines whether mTLS certificate-binding validation applies to a request.
   *
   * Validation is triggered when mTLS is enabled AND either:
   * - it is required by configuration, OR
   * - the access token carries a `cnf.x5t#S256` claim (certificate-bound).
   *
   * DPoP-bound tokens (`cnf.jkt`) are handled by the DPoP path; a token carries
   * at most one confirmation method.
   *
   * @method shouldVerifyMtls
   * @param accessTokenClaims - The verified access token claims
   * @returns `true` if mTLS validation should be enforced
   */
  function shouldVerifyMtls(accessTokenClaims: DPoPJWTPayload): boolean {
    if (!mtlsEnabled) {
      return false;
    }

    return mtlsRequired || isMtlsBound(accessTokenClaims);
  }

  function getToken(): TokenInfo {
    const TOKEN_RE = /^(Bearer|DPoP) (.+)$/i;
    const auth = headers.authorization;

    let fromHeader: string | undefined;

    if (typeof auth === 'string') {
      // Check for correct Authorization HTTP Header format
      const { length } = auth.split(' ');
      if (length !== 2) {
        throw new InvalidRequestError('', false);
      }

      const match = auth.match(TOKEN_RE);
      if (match) {
        fromHeader = match[2];
      }
    }

    const locations: TokenInfo[] = [];
    if (fromHeader) {
      locations.push({ location: 'header', jwt: fromHeader });
    }

    if (typeof query?.access_token === 'string') {
      locations.push({ location: 'query', jwt: query.access_token });
    }

    const hasBodyToken = typeof body?.access_token === 'string';
    if (hasBodyToken && isUrlEncoded) {
      locations.push({ location: 'body', jwt: body.access_token as string });
    }

    if (locations.length === 0) {
      if (hasBodyToken && !isUrlEncoded) {
        throw new InvalidRequestError('', false);
      }
      if (dpopEnabled && 'dpop' in headers) {
        throw new InvalidRequestError('', false);
      }
      if (typeof auth === 'string') {
        throw new InvalidRequestError('', false);
      }
      throw new UnauthorizedError();
    }
    if (locations.length > 1)
      throw new InvalidRequestError(
        'More than one method used for authentication'
      );

    return locations[0];
  }

  /**
   * Validates the Authorization scheme based on DPoP configuration.
   *
   * - If DPoP is enabled and required, expect 'DPoP' scheme.
   * - If DPoP is enabled but not required, allow 'DPoP' or 'Bearer'.
   * - If DPoP is disabled, only allow 'Bearer'.
   *
   * @method verify
   * @throws InvalidRequestError if the scheme is invalid
   * @throws UnauthorizedError if the scheme is not allowed
   */
  async function verify(): Promise<VerifyJwtResult> {
    url = normalizeUrl(url, 'request');

    // Validate request options
    if (typeof method !== 'string' || method.length === 0) {
      throw new InvalidRequestError('Invalid HTTP method received in request');
    }

    // Extract the token from the request headers, query, or body.
    if (dpopEnabled && 'dpop' in headers && !('authorization' in headers)) {
      throw new InvalidRequestError('', false);
    }

    const { jwt, location } = getToken();

    // Determine if the token is from the header and set the flag.
    hasNonHeaderToken = ['query', 'body'].includes(location);

    if (!dpopEnabled) {
      if (authScheme && authScheme !== 'bearer') {
        // @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        throw new InvalidRequestError('', false);
      }
    } else if (dpopRequired) {
      // Perform initial DPoP pre-checks
      assertDPoPRequest(headers);
    } else {
      // When auth scheme is `dpop` but `dpop` proof is not present,
      if (authScheme === 'dpop' && typeof headers.dpop !== 'string') {
        throw new InvalidRequestError('', false);
      }

      // When the scheme is present but neither `dpop` nor `bearer`,
      // When scheme is `undefined` we don't necessarily need to throw an error because the token can be sent via `query` or `body` as-well.
      if (authScheme && !['dpop', 'bearer'].includes(authScheme)) {
        // @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        throw new UnauthorizedError();
      }
    }

    // Pass request context to JWT verifier for MCD issuer resolution
    const verifiedJwt = await verifyJwt(jwt, {
      url: requestOptions.url,
      headers: headers as Record<string, string | string[] | undefined>,
    });
    const accessTokenClaims = verifiedJwt.payload as DPoPJWTPayload;

    if (
      authScheme === 'bearer' &&
      isDPoPBound(accessTokenClaims) &&
      dpopEnabled &&
      !dpopRequired
    ) {
      // In "allowed" DPoP mode, if the token is DPoP-bound but sent with Bearer scheme,
      // we throw an InvalidTokenError to indicate that the token is not valid for Bearer.
      // mTLS-bound tokens (cnf.x5t#S256) legitimately use Bearer and are excluded here.
      throw new InvalidTokenError(
        'DPoP-bound token requires the DPoP authentication scheme, not Bearer.'
      );
    }

    if (shouldVerifyDPoP(accessTokenClaims)) {
      await verifyDPoP({
        jwt,
        accessTokenClaims,
        url,
        headers,
        method,
        iatOffset,
        iatLeeway,
        supportedAlgorithms: SUPPORTED_ALGORITHMS,
      });
    } else if (shouldVerifyMtls(accessTokenClaims)) {
      // Certificate-bound access token (RFC 8705). Validate that the certificate
      // presented on the TLS connection matches the token's cnf.x5t#S256 claim.
      // DPoP is intentionally checked first and shadows mTLS: a token carries at
      // most one confirmation method, and a DPoP proof header (if present) routes
      // the request to the DPoP path above regardless of any cnf.x5t#S256 claim.
      verifyMtls({ accessTokenClaims, clientCertificate });
    }

    return verifiedJwt;
  }

  /**
   * Adds `WWW-Authenticate` challenges to the given AuthError based on DPoP support and the current auth scheme.
   *
   * - If DPoP is disabled, only a Bearer challenge is returned.
   * - If DPoP is required, only a DPoP challenge is returned.
   * - If DPoP is optional, both Bearer and DPoP challenges are returned but `error` and `error_description` will be added based on the authentication `scheme`.
   *
   * @method applyAuthChallenges
   * @param e - The thrown AuthError instance
   * @param supportedAlgs - List of supported JWS algorithms for DPoP
   * @returns The same error object with headers appended (if applicable)
   */
  function applyAuthChallenges(
    error: unknown,
    supportedAlgs: string[] = SUPPORTED_ALGORITHMS
  ): unknown {
    if (!dpopEnabled || !(error instanceof UnauthorizedError)) return error;

    const authError = error as AuthError;
    const errorCode = authError.code;
    const description = authError.message;
    const challenges: string[] = [];
    const hasBearer = authScheme === 'bearer';
    const hasDpop = authScheme === 'dpop';
    const hasErrorCode = typeof errorCode === 'string' && errorCode.length > 0;
    const safeDescription = description.replace(/"/g, "'");

    const buildChallenge = (
      scheme: 'bearer' | 'dpop',
      includeError: boolean
    ): string => {
      const algs = supportedAlgs.join(' ');

      if (scheme === 'dpop') {
        return includeError
          ? `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${algs}"`
          : `DPoP algs="${algs}"`;
      } else {
        return includeError
          ? `Bearer realm="api", error="${errorCode}", error_description="${safeDescription}"`
          : `Bearer realm="api"`;
      }
    };

    if (dpopRequired) {
      challenges.push(buildChallenge('dpop', hasErrorCode));
    } else {
      const mode =
        !hasBearer && !hasDpop ? 'none' : hasBearer ? 'bearer' : 'dpop';

      switch (mode) {
        case 'none':
          /*
           * If the authentication `scheme` is missing, the token may still have been provided via `query` or `body` parameters.
           * In these cases, the `Bearer` challenge may include `error` attributes depending on the specific error raised.
           * For errors of type `UnauthorizedError` (which do not have an `error` code), the challenge will not include `error` attributes.
           * For other errors (such as InvalidRequestError), the `Bearer` challenge should include the `error` attribute.
           */
          challenges.push(
            buildChallenge('bearer', hasNonHeaderToken ? hasErrorCode : false)
          );
          challenges.push(buildChallenge('dpop', false));
          break;
        case 'bearer':
          challenges.push(buildChallenge('bearer', hasErrorCode));
          challenges.push(buildChallenge('dpop', false));
          break;
        case 'dpop':
          challenges.push(buildChallenge('bearer', false));
          challenges.push(buildChallenge('dpop', hasErrorCode));
          break;
      }
    }

    if (challenges.length > 0) {
      (error as UnauthorizedError).headers = {
        'WWW-Authenticate': challenges.join(', '),
      };
    }

    return error;
  }

  return {
    shouldVerifyDPoP,
    shouldVerifyMtls,
    getToken,
    verify,
    applyAuthChallenges,
  };
}

export default tokenVerifier;
export {
  normalizeHeaders,
  getAuthScheme,
  assertValidDPoPOptions,
  assertValidMtlsOptions,
};
export type {
  DPoPJWTPayload,
  AuthOptions,
  DPoPOptions,
  MtlsOptions,
  QueryLike,
  BodyLike,
  RequestLike,
  HeadersLike,
};
