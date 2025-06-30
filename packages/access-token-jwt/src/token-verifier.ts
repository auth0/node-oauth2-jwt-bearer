import { InvalidRequestError, UnauthorizedError } from 'oauth2-bearer';

import type {
  VerifyJwt,
  JwtVerifierOptions,
  VerifyJwtResult,
} from './jwt-verifier';

import { verifyDPoP, assertDPoPRequest, DPoPJWTPayload } from './dpop-verifier';

const DEFAULT_DPOP_ENABLED = true; // DPoP is enabled by default.
const DEFAULT_DPOP_REQUIRED = false; // DPoP is allowed by default.
const DEFAULT_IAT_OFFSET = 300; // 5 minutes.
const DEFAULT_IAT_LEEWAY = 30; // 30 seconds.
const SUPPORTED_ALGORITHMS = ['ES256']; // Supports only `ES256`.

interface DPoPOptions {
  enabled?: boolean;
  required?: boolean;
  iatOffset?: number;
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

export type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  dpop?: string;
};

type QueryLike = Record<string, unknown> & { access_token?: string };
type BodyLike = QueryLike;

type TokenInfo = {
  location: 'header' | 'query' | 'body';
  jwt: string;
};

export type RequestLike = Record<string, unknown> & {
  headers: HeadersLike;
  url: string;
  method: string;
  query?: QueryLike;
  body?: BodyLike;
  isUrlEncoded?: boolean; // true if the request's Content-Type is `application/x-www-form-urlencoded`
};

// Normalize headers to a lowercase key object
function normalizeHeaders(input: unknown): HeadersLike {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return {};
  }

  const headers: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
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

function tokenVerifier(
  verifyJwt: VerifyJwt,
  options: AuthOptions = {},
  requestOptions: RequestLike
) {
  // Extract headers, url, and method from requestOptions
  const headers = normalizeHeaders(requestOptions?.headers || {});
  const url = requestOptions?.url;
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
  let isTokenFromHeader = false;

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
    // Extract the token from the request headers, query, or body.
    const { jwt, location } = getToken();
    isTokenFromHeader = location === 'header';

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
   * - If DPoP is disabled, no headers are added.
   * - If DPoP is required, only a DPoP challenge is returned.
   * - If DPoP is optional, both Bearer and DPoP challenges may be returned based on the scheme present.
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
    const challenges: string[] = [];
    const hasBearer = authScheme === 'bearer';
    const hasDpop = authScheme === 'dpop';
    const errorCode = (error as AuthError)?.code;
    const description = (error as AuthError)?.message ?? '';
    const hasErrorCode = typeof errorCode === 'string' && errorCode.length > 0;
    const safeDescription = description.replace(/"/g, "'");

    const buildChallenge = (
      scheme: 'bearer' | 'dpop',
      includeError = true
    ): string => {
      const algs = supportedAlgs.join(' ');
      const hasError = includeError && hasErrorCode;

      const dpopChallenge = hasError
        ? `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${algs}"`
        : `DPoP algs="${algs}"`;
      const bearerChallenge = hasError
        ? `Bearer realm="api", error="${errorCode}", error_description="${safeDescription}"`
        : `Bearer realm="api"`;

      return scheme === 'dpop' ? dpopChallenge : bearerChallenge;
    };

    if (dpopRequired) {
      challenges.push(buildChallenge('dpop'));
    } else {
      const mode =
        !hasBearer && !hasDpop
          ? 'none'
          : hasBearer
          ? 'bearer'
          : hasDpop
          ? 'dpop'
          : 'both';

      if (mode === 'both') return error;

      switch (mode) {
        case 'none':
          challenges.push(
            buildChallenge('bearer', isTokenFromHeader ? false : hasErrorCode)
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
        // default:
        //   challenges.push(buildChallenge('bearer', hasErrorCode));
        //   challenges.push(buildChallenge('dpop', hasErrorCode));
        //   break;
      }
    }

    if (challenges.length > 0) {
      (error as any).headers = {
        'WWW-Authenticate': challenges.join(', '),
      };
    }

    return error;
  }

  return {
    verify: verify,
    applyAuthChallenges,
  };
}

export default tokenVerifier;
export type { DPoPJWTPayload, AuthOptions, DPoPOptions };
