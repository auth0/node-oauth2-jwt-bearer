import { InvalidRequestError, UnauthorizedError } from 'oauth2-bearer';
import { strict as assert } from 'assert';

import type {
  VerifyJwt,
  JwtVerifierOptions,
  VerifyJwtResult,
} from './jwt-verifier';

import { ASYMMETRIC_ALGS as SUPPORTED_ALGORITHMS } from './jwt-verifier';

import { normalizeUrl, verifyDPoP, assertDPoPRequest, DPoPJWTPayload } from './dpop-verifier';

const DEFAULT_DPOP_ENABLED = true; // DPoP is enabled by default.
const DEFAULT_DPOP_REQUIRED = false; // DPoP is allowed by default.
const DEFAULT_IAT_OFFSET = 300; // 5 minutes.
const DEFAULT_IAT_LEEWAY = 30; // 30 seconds.

/**
 * Options that control Demonstration of Proof-of-Possession (DPoP) handling.
 *
 * @remarks
 * DPoP (RFC 9449) is an application-level mechanism to sender-constrain OAuth 2.0
 * access/refresh tokens by proving possession of a private key. This SDK supports
 * validating DPoP proofs on incoming requests when enabled.
 *
 *
 * Behavior matrix:
 *
 * - <code>enabled: true</code>, <code>required: false</code> — <strong>Default.</strong> Accept Bearer and DPoP. Validate proofs when present.
 * - <code>enabled: false</code>, <code>required: false</code> — <strong>Bearer-only.</strong> DPoP proofs/tokens are ignored.
 * - <code>enabled: false</code>, <code>required: true</code> — <strong>Misconfiguration.</strong> DPoP is disabled, so <code>required</code> is ignored; effective behavior is Bearer-only.
 * - <code>enabled: true</code>, <code>required: true</code> — <strong>DPoP-only.</strong> Reject non-DPoP Bearer tokens.
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
 *
 * @see https://www.rfc-editor.org/rfc/rfc9449
 * @see https://www.rfc-editor.org/rfc/rfc3986#section-6 (URI normalization)
 */
interface DPoPOptions {
  /**
   * Enables DPoP support.
   *
   * When `true`, requests may use DPoP (Authorization scheme `DPoP` plus a `DPoP` header)
   * and the middleware will validate proofs. When `false`, DPoP headers/tokens are ignored
   * and only standard Bearer tokens are accepted.
   *
   * @default true
   * @example
   * // Accept both Bearer and DPoP (default):
   * auth({ dpop: { enabled: true, required: false } })
   *
   * @example
   * // Bearer-only:
   * auth({ dpop: { enabled: false } })
   */
  enabled?: boolean;

  /**
   * Requires DPoP tokens exclusively when DPoP is enabled.
   *
   * When `enabled: true` and `required: true`, only DPoP tokens are accepted and non-DPoP
   * Bearer tokens are rejected. When `enabled: false`, using this flag results in a misconfiguration (Bearer-only mode).
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
   * Proofs older than `iatOffset` (relative to current server time) are rejected to
   * reduce replay risk. Typical values are a few minutes.
   *
   * Applied only when `enabled: true` and a DPoP proof is present.
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
   * Some clients may have slightly skewed clocks. A small positive leeway prevents
   * valid proofs from being rejected when `iat` is a bit in the future.
   *
   * Applied only when `enabled: true` and a DPoP proof is present.
   *
   * @default 30  // 30 seconds
   * @example
   * // Allow up to 60 seconds of client/server clock skew
   * auth({ dpop: { enabled: true, iatLeeway: 60 } })
   */
  iatLeeway?: number;
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
};

function isJsonObject(input: unknown): boolean {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

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
    typeof dpopOptions === 'object' &&
      dpopOptions !== null &&
      !Array.isArray(dpopOptions),
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
  const authScheme = getAuthScheme(headers)?.toLowerCase();
  // Extract DPoP options from the provided options or use defaults
  const {
    dpop: {
      enabled: dpopEnabled = DEFAULT_DPOP_ENABLED,
      required: dpopRequired = DEFAULT_DPOP_REQUIRED,
      iatOffset = DEFAULT_IAT_OFFSET,
      iatLeeway = DEFAULT_IAT_LEEWAY,
    } = {},
  } = options;
  let hasNonHeaderToken = false;
  let url = requestOptions?.url;
  
  /*
   * Validates the request options to ensure they are in the expected format.
   * Throws InvalidRequestError if any of the options are invalid.
   */
  function validateRequestOptions(): void {
    if (typeof method !== 'string' || method.length === 0) {
      throw new InvalidRequestError('Invalid HTTP method received in request');
    }

    if (query && isJsonObject(query) === false) {
      throw new InvalidRequestError(
        "Request 'query' parameter must be a valid JSON object"
      );
    }

    if (body && isJsonObject(body) === false) {
      throw new InvalidRequestError(
        "Request 'body' parameter must be a valid JSON object"
      );
    }
  }

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
    const hasBoundToken = 'cnf' in accessTokenClaims;

    return dpopRequired || isDPoPScheme || hasBoundToken || hasDPoPHeader;
  }

  function getToken(): TokenInfo {
    const TOKEN_RE = /^(Bearer|DPoP) (.+)$/i;

    const auth = headers.authorization;
    const match = typeof auth === 'string' && auth.match(TOKEN_RE);
    const fromHeader = match && match[2];

    const locations: TokenInfo[] = [];
    if (fromHeader) {
      locations.push({ location: 'header', jwt: fromHeader });
    }

    if (typeof query?.access_token === 'string') {
      locations.push({ location: 'query', jwt: query.access_token });
    }

    if (typeof body?.access_token === 'string' && isUrlEncoded) {
      locations.push({ location: 'body', jwt: body.access_token });
    }
    
    if (locations.length === 0) throw new UnauthorizedError();
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
    validateRequestOptions();

    // Extract the token from the request headers, query, or body.
    const { jwt, location } = getToken();

    // Determine if the token is from the header and set the flag.
    hasNonHeaderToken = ['query', 'body'].includes(location);

    if (!dpopEnabled) {
      if (authScheme && authScheme !== 'bearer') {
        // @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        throw new UnauthorizedError();
      }
    } else if (dpopRequired) {
      // Perform initial DPoP pre-checks
      assertDPoPRequest(headers);
    } else {
      // When auth scheme is `dpop` but `dpop` proof is not present,
      if (authScheme === 'dpop' && typeof headers.dpop !== 'string') {
        throw new InvalidRequestError(
          'Operation indicated DPoP use but the request has no DPoP HTTP Header'
        );
      }

      // When auth scheme is `bearer` but `dpop` proof is present,
      if (authScheme === 'bearer' && typeof headers.dpop === 'string') {
        throw new InvalidRequestError(
          "Operation indicated DPoP use but the request's Authorization HTTP Header scheme is not DPoP"
        );
      }

      // When the scheme is present but neither `dpop` nor `bearer`,
      // When scheme is `undefined` we don't necessarily need to throw an error because the token can be sent via `query` or `body` as-well.
      if (authScheme && !['dpop', 'bearer'].includes(authScheme)) {
        // @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        throw new UnauthorizedError();
      }
    }

    const verifiedJwt = await verifyJwt(jwt);
    const accessTokenClaims = verifiedJwt.payload as DPoPJWTPayload;

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
    }

    return verifiedJwt;
  }

  /**
   * Adds `WWW-Authenticate` challenges to the given AuthError based on DPoP support and the current auth scheme.
   *
   * - If DPoP is disabled, only a Bearer challenge is returned.
   * - If DPoP is required, only a DPoP challenge is returned.
   * - If DPoP is optional, both Bearer and DPoP challenges are returned but `error` and `error_description` will be added based on the HTTP `scheme`.
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
      includeError = true
    ): string => {
      const algs = supportedAlgs.join(' ');
      const hasError = includeError && hasErrorCode;

      if (scheme === 'dpop') {
        return hasError
          ? `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${algs}"`
          : `DPoP algs="${algs}"`;
      } else {
        return hasError
          ? `Bearer realm="api", error="${errorCode}", error_description="${safeDescription}"`
          : `Bearer realm="api"`;
      }
    };

    if (dpopRequired) {
      challenges.push(buildChallenge('dpop'));
    } else {
      const mode =
        !hasBearer && !hasDpop
          ? 'none'
          : hasBearer
          ? 'bearer'
          : 'dpop';

      switch (mode) {
        case 'none':
          /*
           * If the authorization `scheme` is missing, the token may still have been provided via `query` or `body` parameters.
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
          challenges.push(buildChallenge('dpop', hasErrorCode));
          challenges.push(buildChallenge('bearer', false));
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
    getToken,
    verify,
    applyAuthChallenges,
  };
}

export default tokenVerifier;
export {
  isJsonObject,
  normalizeHeaders,
  getAuthScheme,
  assertValidDPoPOptions,
};
export type {
  DPoPJWTPayload,
  AuthOptions,
  DPoPOptions,
  QueryLike,
  BodyLike,
  RequestLike,
  HeadersLike,
};
