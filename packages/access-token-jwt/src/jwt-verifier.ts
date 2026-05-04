import { strict as assert } from 'assert';
import { TextEncoder } from 'util';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { jwtVerify, decodeJwt, decodeProtectedHeader, importSPKI, importJWK, createLocalJWKSet } from 'jose';
import type { JWTPayload, JWSHeaderParameters, JWK, JSONWebKeySet, KeyLike } from 'jose';
import { InvalidTokenError, InvalidRequestError } from 'oauth2-bearer';
import discovery from './discovery';
import getKeyFn from './get-key-fn';
import validate, { defaultValidators, Validators } from './validate';

/**
 * A static public key for asymmetric JWT verification without discovery or a
 * remote JWKS endpoint.  Accepted forms:
 *
 * - `string` – PEM-encoded SPKI public key (requires `tokenSigningAlg` or `alg`)
 * - `JWK` – a single JWK object (`{ kty, n, e, … }`)
 * - `JSONWebKeySet` – an inline JWK Set (`{ keys: [...] }`)
 */
export type PublicKeyInput = string | JWK | JSONWebKeySet;

// MCD Types
export interface AsymmetricIssuerConfig {
  issuer: string;
  alg?: string;
  jwksUri?: string;
  /**
   * A static public key used to verify tokens from this issuer without
   * hitting a remote JWKS endpoint.  Mutually exclusive with `jwksUri`.
   */
  publicKey?: PublicKeyInput;
}

export interface SymmetricIssuerConfig {
  issuer: string;
  alg: string;
  secret: string;
}

export type IssuerConfig = AsymmetricIssuerConfig | SymmetricIssuerConfig;

export interface IssuerResolverContext {
  url: URL;
  headers: Record<string, string | string[] | undefined>;
}

export type IssuerResolverResult = string[] | IssuerConfig[];

export type IssuerResolverFunction = (
  context: IssuerResolverContext
) => Promise<IssuerResolverResult> | IssuerResolverResult;

export interface MCDOptions {
  issuers: string | string[] | IssuerConfig[] | IssuerResolverFunction;
}

export interface RequestContext {
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface JwtVerifierOptions {
  /**
   * Base url, used to find the authorization server's app metadata per
   * https://datatracker.ietf.org/doc/html/rfc8414
   * You can pass a full url including `.well-known` if your discovery lives at
   * a non standard path.
   * REQUIRED (if you don't include {@Link AuthOptions.jwksUri} and
   * {@Link AuthOptions.issuer})
   * You can also provide the `ISSUER_BASE_URL` environment variable.
   */
  issuerBaseURL?: string;

  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   * REQUIRED: You can also provide the `AUDIENCE` environment variable.
   */
  audience?: string | string[];

  /**
   * Expected JWT "iss" (Issuer) Claim value.
   * REQUIRED (if you don't include {@Link AuthOptions.issuerBaseURL})
   * You can also provide the `ISSUER` environment variable.
   */
  issuer?: string;

  /**
   * Url for the authorization server's JWKS to find the public key to verify
   * an Access Token JWT signed with an asymmetric algorithm.
   * REQUIRED (if you don't include {@Link AuthOptions.issuerBaseURL})
   * You can also provide the `JWKS_URI` environment variable.
   */
  jwksUri?: string;

  /**
   * An instance of http.Agent or https.Agent to pass to the http.get or
   * https.get method options. Use when behind an http(s) proxy.
   */
  agent?: HttpAgent | HttpsAgent;

  /**
   * Duration in ms for which no more HTTP requests to the JWKS Uri endpoint
   * will be triggered after a previous successful fetch.
   * Default is 30000.
   */
  cooldownDuration?: number;

  /**
   * Timeout in ms for HTTP requests to the JWKS and Discovery endpoint. When
   * reached the request will be aborted.
   * Default is 5000.
   */
  timeoutDuration?: number;

  /**
   * Maximum time (in milliseconds) between successful HTTP requests to the
   * JWKS and Discovery endpoint.
   * Default is 600000 (10 minutes).
   * @deprecated Use cache.ttl instead for more granular control
   */
  cacheMaxAge?: number;

  /**
   * Cache configuration for OIDC discovery metadata and JWKS.
   * Caching reduces network requests and improves performance, especially
   * in MCD scenarios with multiple issuers.
   *
   * Default behavior (if not specified):
   * - Discovery cache: 100 entries, 10 minute TTL
   * - JWKS cache: 100 entries, 10 minute TTL
   */
  cache?: {
    /**
     * OIDC discovery metadata cache configuration.
     * Caches responses from /.well-known/openid-configuration endpoints.
     */
    discovery?: {
      /**
       * Maximum number of issuer discovery metadata to cache.
       * When this limit is reached, least recently used entries are evicted.
       * Default: 100
       */
      maxEntries?: number;
      /**
       * Time-to-live for cached discovery metadata in milliseconds.
       * Default: 600000 (10 minutes)
       */
      ttl?: number;
    };
    /**
     * JWKS (JSON Web Key Set) cache configuration.
     * Caches responses from /.well-known/jwks.json endpoints.
     */
    jwks?: {
      /**
       * Maximum number of JWKS to cache.
       * When this limit is reached, least recently used entries are evicted.
       * Default: 100
       */
      maxEntries?: number;
      /**
       * Time-to-live for cached JWKS in milliseconds.
       * Default: 600000 (10 minutes)
       */
      ttl?: number;
    };
  };

  /**
   * Pass in custom validators to override the existing validation behavior on
   * standard claims or add new validation behavior on custom claims.
   *
   * ```js
   *  {
   *    validators: {
   *      // Disable issuer validation by passing `false`
   *      iss: false,
   *      // Add validation for a custom claim to equal a passed in string
   *      org_id: 'my_org_123'
   *      // Add validation for a custom claim, by passing in a function that
   *      // accepts:
   *      // roles: the value of the claim
   *      // claims: an object containing the JWTPayload
   *      // header: an object representing the JWTHeader
   *      roles: (roles, claims, header) => roles.includes('editor') && claims.isAdmin
   *    }
   *  }
   * ```
   */
  validators?: Partial<Validators>;

  /**
   * Clock tolerance (in secs) used when validating the `exp` and `iat` claim.
   * Defaults to 5 secs.
   */
  clockTolerance?: number;

  /**
   * Maximum age (in secs) from when a token was issued to when it can no longer
   * be accepted.
   */
  maxTokenAge?: number;

  /**
   * If set to `true` the token validation will strictly follow
   * 'JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens'
   * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-access-token-jwt-12
   * Defaults to false.
   */
  strict?: boolean;

  /**
   * Secret to verify an Access Token JWT signed with a symmetric algorithm.
   * By default this SDK validates tokens signed with asymmetric algorithms.
   */
  secret?: string;

  /**
   * A static public key for verifying an Access Token JWT signed with an
   * asymmetric algorithm, without requiring OIDC discovery or a remote JWKS
   * endpoint.
   *
   * Accepted formats:
   * - PEM-encoded SPKI string — requires `tokenSigningAlg`
   * - A JWK object `{ kty, n, e, … }` — `alg` field in the JWK or
   *   `tokenSigningAlg` must identify the algorithm
   * - An inline JWK Set `{ keys: [...] }` — key selection uses the token's
   *   `kid` header and each key's own `alg` field
   *
   * Mutually exclusive with `secret`, `jwksUri`, and `issuerBaseURL`.
   *
   * ```js
   * jwtVerifier({
   *   issuer: 'https://issuer.example.com/',
   *   audience: 'https://api/',
   *   publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
   *   tokenSigningAlg: 'RS256',
   * })
   * ```
   */
  publicKey?: PublicKeyInput;

  /**
   * You must provide this if your tokens are signed with symmetric algorithms
   * and it must be one of HS256, HS384 or HS512.
   * You may provide this if your tokens are signed with asymmetric algorithms
   * and, if provided, it must be one of RS256, RS384, RS512, PS256, PS384,
   * PS512, ES256, ES256K, ES384, ES512 or EdDSA (case-sensitive).
   */
  tokenSigningAlg?: string;

  /**
   * MCD (Multiple Custom Domains) Support:
   * Configure multiple issuers for JWT validation.
   * When present, the SDK operates in MCD mode.
   *
   * Examples:
   * - Static issuers: { issuers: ['https://tenant1.auth0.com', 'https://tenant2.auth0.com'] }
   * - With config: { issuers: [{ issuer: 'https://...', alg: 'RS256' }] }
   * - Dynamic resolver: { issuers: async (context) => [...] }
   *
   * Cannot be used with issuerBaseURL.
   */
  mcd?: MCDOptions;
}

export interface VerifyJwtResult {
  /**
   * The Access Token JWT header.
   */
  header: JWSHeaderParameters;
  /**
   * The Access Token JWT payload.
   */
  payload: JWTPayload;
  /**
   * The raw Access Token JWT
   */
  token: string;
}

export type VerifyJwt = (
  jwt: string,
  requestContext?: RequestContext
) => Promise<VerifyJwtResult>;

export const ASYMMETRIC_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES256K',
  'ES384',
  'ES512',
  'EdDSA',
];
const SYMMETRIC_ALGS = ['HS256', 'HS384', 'HS512'];

const jwtVerifier = ({
  issuerBaseURL = process.env.ISSUER_BASE_URL as string,
  jwksUri = process.env.JWKS_URI as string,
  issuer = process.env.ISSUER as string,
  audience = process.env.AUDIENCE as string,
  secret = process.env.SECRET as string,
  publicKey,
  tokenSigningAlg = process.env.TOKEN_SIGNING_ALG as string,
  mcd,
  agent,
  cooldownDuration = 30000,
  timeoutDuration = 5000,
  cacheMaxAge = 600000,
  cache,
  clockTolerance = 5,
  maxTokenAge,
  strict = false,
  validators: customValidators,
}: JwtVerifierOptions): VerifyJwt => {

  // Validation: Ensure proper configuration
  assert(
    mcd || issuerBaseURL || (issuer && (jwksUri || secret || publicKey)),
    "You must provide 'mcd', 'issuerBaseURL', or both 'issuer' and ('jwksUri', 'secret', or 'publicKey')"
  );
  assert(
    !(mcd && issuerBaseURL),
    "You must not provide both 'mcd' and 'issuerBaseURL'"
  );
  assert(
    !(mcd && issuer),
    "You must not provide both 'mcd' and 'issuer'. Use 'mcd' for multi-issuer mode."
  );
  assert(
    !(mcd && jwksUri),
    "You must not provide both 'mcd' and 'jwksUri'. Use 'mcd' for multi-issuer mode."
  );
  assert(
    !(secret && jwksUri),
    "You must not provide both a 'secret' and 'jwksUri'"
  );
  assert(
    !(publicKey && jwksUri),
    "You must not provide both a 'publicKey' and 'jwksUri'"
  );
  assert(
    !(publicKey && secret),
    "You must not provide both a 'publicKey' and 'secret'"
  );
  assert(
    !(publicKey && issuerBaseURL),
    "You must not provide both a 'publicKey' and 'issuerBaseURL'"
  );
  assert(
    !(mcd && secret),
    'Cannot use top-level "secret" with mcd mode. ' +
    'Specify secrets per-issuer in the issuer configuration: ' +
    '{ issuer: "...", secret: "...", alg: "HS256" }'
  );
  assert(
    !(mcd && publicKey),
    'Cannot use top-level "publicKey" with mcd mode. ' +
    'Specify publicKey per-issuer in the issuer configuration: ' +
    '{ issuer: "...", publicKey: "..." }'
  );
  assert(audience, "An 'audience' is required to validate the 'aud' claim");
  assert(
    !secret || (secret && tokenSigningAlg),
    "You must provide a 'tokenSigningAlg' for validating symmetric algorithms"
  );
  assert(
    secret || !tokenSigningAlg || ASYMMETRIC_ALGS.includes(tokenSigningAlg),
    `You must supply one of ${ASYMMETRIC_ALGS.join(
      ', '
    )} for 'tokenSigningAlg' to validate asymmetrically signed tokens`
  );
  assert(
    !secret || (tokenSigningAlg && SYMMETRIC_ALGS.includes(tokenSigningAlg)),
    `You must supply one of ${SYMMETRIC_ALGS.join(
      ', '
    )} for 'tokenSigningAlg' to validate symmetrically signed tokens`
  );

  // Helper: Normalize issuer URL
  const normalizeIssuerUrl = (url: string): string => {
    try {
      let urlToParse = url;
      if (!url.match(/^https?:\/\//i)) {
        urlToParse = `https://${url}`;
      }

      const parsed = new URL(urlToParse);
      
      // Security check: Warn about HTTP in production
      if (parsed.protocol === 'http:' && process.env.NODE_ENV === 'production') {
        throw new InvalidRequestError('HTTP issuer URL detected in production environment. Use HTTPS for security.');
      }
      
      // Security check: Detect and warn about potentially sensitive URL components that will be stripped
      const hasUserInfo = parsed.username || parsed.password;
      const hasQuery = parsed.search;
      const hasFragment = parsed.hash;
      
      if (hasUserInfo) {
        throw new InvalidRequestError('Invalid issuer URL: URLs must not contain userinfo (username:password)');
      }
      if (hasQuery) {
        throw new InvalidRequestError('Invalid issuer URL: URLs must not contain query parameters');
      }
      if (hasFragment) {
        throw new InvalidRequestError('Invalid issuer URL: URLs must not contain fragments');
      }
      
      // Normalize: lowercase hostname, remove default ports, ensure no trailing slash
      // Note: parsed.origin automatically excludes userinfo, search, and hash
      let normalized = `${parsed.protocol.toLowerCase()}//${parsed.hostname.toLowerCase()}`;
      if (
        (parsed.protocol === 'https:' && parsed.port && parsed.port !== '443') ||
        (parsed.protocol === 'http:' && parsed.port && parsed.port !== '80')
      ) {
        normalized += `:${parsed.port}`;
      }
      if (parsed.pathname && parsed.pathname !== '/') {
        normalized += parsed.pathname.replace(/\/$/, '');
      }
      return normalized;
    } catch (error) {
      // Re-throw security validation errors (InvalidRequestError)
      if (error instanceof InvalidRequestError) {
        throw error;
      }
      // Only catch URL parsing errors, return original URL
      return url;
    }
  };

  // Helper: Normalize issuer config
  const normalizeIssuerConfig = (
    config: string | IssuerConfig
  ): IssuerConfig => {
    if (typeof config === 'string') {
      return { issuer: normalizeIssuerUrl(config) } as AsymmetricIssuerConfig;
    }
    return { ...config, issuer: normalizeIssuerUrl(config.issuer) };
  };

  // MCD Support: Validate mcd configuration
  if (mcd) {
    assert(mcd.issuers, "Invalid MCD configuration: 'issuers' is required");

    // Validate static issuer configurations at initialization
    if (typeof mcd.issuers !== 'function') {
      const staticIssuers = Array.isArray(mcd.issuers)
        ? mcd.issuers
        : [mcd.issuers];

      staticIssuers.forEach((issuerConfig) => {
        // Normalize and validate URL (this will throw errors for security issues)
        normalizeIssuerConfig(issuerConfig);

        // Skip string-only configs (no algorithm specified)
        if (typeof issuerConfig === 'string') return;

        const hasSecret = 'secret' in issuerConfig && issuerConfig.secret;
        const hasPublicKey = 'publicKey' in issuerConfig && (issuerConfig as AsymmetricIssuerConfig).publicKey;
        const hasJwksUri = 'jwksUri' in issuerConfig && (issuerConfig as AsymmetricIssuerConfig).jwksUri;
        const configuredAlg = issuerConfig.alg;

        // publicKey and jwksUri are mutually exclusive per issuer
        if (hasPublicKey && hasJwksUri) {
          throw new Error(
            `Configuration error: Issuer '${issuerConfig.issuer}' provides both 'publicKey' and 'jwksUri'. These are mutually exclusive.`
          );
        }

        // publicKey and secret are mutually exclusive per issuer
        if (hasPublicKey && hasSecret) {
          throw new Error(
            `Configuration error: Issuer '${issuerConfig.issuer}' provides both 'publicKey' and 'secret'. Use 'publicKey' for asymmetric and 'secret' for symmetric verification.`
          );
        }

        // Check if symmetric algorithm configured without secret
        if (
          configuredAlg &&
          SYMMETRIC_ALGS.includes(configuredAlg) &&
          !hasSecret
        ) {
          throw new Error(
            `Configuration error: Issuer '${issuerConfig.issuer}' specifies symmetric algorithm '${configuredAlg}' but no secret provided. Either provide a secret or use an asymmetric algorithm (${ASYMMETRIC_ALGS.join(', ')}).`
          );
        }

        // Check if secret provided with asymmetric algorithm
        if (
          hasSecret &&
          configuredAlg &&
          ASYMMETRIC_ALGS.includes(configuredAlg)
        ) {
          throw new Error(
            `Configuration error: Issuer '${issuerConfig.issuer}' provides a secret but specifies asymmetric algorithm '${configuredAlg}'. Symmetric algorithms are: ${SYMMETRIC_ALGS.join(', ')}.`
          );
        }

        // Check if secret provided without algorithm
        if (hasSecret && !configuredAlg) {
          throw new Error(
            `Configuration error: Issuer '${issuerConfig.issuer}' provides a secret but no 'alg' specified. Specify one of: ${SYMMETRIC_ALGS.join(', ')}.`
          );
        }
      });
    }
  }

  const getDiscovery = discovery({
    agent,
    timeoutDuration,
    cacheMaxAge,
    cache,
  });

  const getKeyFnGetter = getKeyFn({
    agent,
    cooldownDuration,
    timeoutDuration,
    cacheMaxAge,
    secret,
    cache,
  });

  // Lazy public key import caches — key parsing is expensive; cache once per unique key.
  // PEM strings are keyed by (pem + "\0" + alg) since the same PEM with a different
  // algorithm would produce a different CryptoKey.
  const _pemKeyCache = new Map<string, Promise<KeyLike>>();
  // JWK and JWK Set objects are keyed by object identity via WeakMap so that they
  // can be garbage-collected when the verifier itself is no longer referenced.
  const _jwkKeyCache = new WeakMap<object, Promise<KeyLike>>();
  const _jwkSetFnCache = new WeakMap<object, ReturnType<typeof createLocalJWKSet>>();

  // Helper: Early algorithm validation
  const validateAlgorithmEarly = (jwt: string, hasSecret: boolean) => {
    const { alg } = decodeProtectedHeader(jwt);
    
    if (!alg || typeof alg !== 'string') {
      throw new InvalidTokenError('Token header missing or invalid "alg" claim');
    }
    
    if (hasSecret) {
      // For secret-based verification, only allow symmetric algorithms
      if (!SYMMETRIC_ALGS.includes(alg)) {
        throw new InvalidTokenError(
          `Unsupported algorithm "${alg}" for secret-based verification. Supported: ${SYMMETRIC_ALGS.join(', ')}`
        );
      }
    } else {
      // For JWKS-based verification, only allow asymmetric algorithms
      if (!ASYMMETRIC_ALGS.includes(alg)) {
        throw new InvalidTokenError(
          `Unsupported algorithm "${alg}" for JWKS-based verification. Supported: ${ASYMMETRIC_ALGS.join(', ')}`
        );
      }
    }
  };


  /**
   * Helper: Verify and validate JWT signature and claims
   *
   * This helper consolidates the common verification logic used by both
   * MCD (multi-issuer) and single issuer modes. It handles:
   * 1. Setting up claim validators (iss, aud, exp, etc.)
   * 2. Verifying the JWT signature (symmetric or asymmetric)
   * 3. Validating all claims against configured rules
   *
   * @param jwt - The JWT token string to verify
   * @param issuerValue - Expected issuer for 'iss' claim validation
   * @param jwksUriValue - JWKS URI for asymmetric signature verification (RS256, ES256, etc.)
   * @param secretValue - Secret for symmetric signature verification (HS256, HS384, HS512)
   * @param publicKeyValue - Static public key for asymmetric verification without a remote JWKS
   * @param algValue - Expected signing algorithm
   * @param allowedSigningAlgsValue - List of allowed signing algorithms from discovery
   * @returns Verified JWT payload, header, and original token
   */
  const verifyAndValidateJwt = async (
    jwt: string,
    issuerValue: string,
    jwksUriValue: string | undefined,
    secretValue: string | undefined,
    publicKeyValue: PublicKeyInput | undefined,
    algValue: string | undefined,
    allowedSigningAlgsValue: string[] | undefined
  ): Promise<VerifyJwtResult> => {
    // Setup validators: Configure rules for validating JWT claims
    // This combines default validators (iss, aud, exp, iat, etc.) with any custom ones
    // The ||= operator ensures we only set validators once per request
    const validators: Validators = {
      ...defaultValidators(
        issuerValue,
        audience,
        clockTolerance,
        maxTokenAge,
        strict,
        allowedSigningAlgsValue,
        algValue
      ),
      ...customValidators,
    };

    // Verify JWT signature: The verification path depends on the algorithm type
    let payload: JWTPayload;
    let header: JWSHeaderParameters;

    if (secretValue) {
      // Symmetric algorithm verification (HS256, HS384, HS512)
      // These use a shared secret known to both the issuer and verifier.
      // Convert the secret string to a key that jose library can use.
      const keyFn = new TextEncoder().encode(secretValue);
      const result = await jwtVerify(jwt, keyFn, { clockTolerance });
      payload = result.payload;
      header = result.protectedHeader;
    } else if (publicKeyValue) {
      // Static public key verification (RS256, ES256, PS256, etc.)
      // The caller supplied the public key directly — no remote fetch needed.
      // All three branches cache their result so the expensive key-import work
      // is only performed once per unique key across all verification calls.
      if (typeof publicKeyValue === 'string') {
        // PEM SPKI format — algorithm must be specified explicitly
        if (!algValue) {
          throw new InvalidRequestError(
            "You must provide 'tokenSigningAlg' (or 'alg' in the issuer config) when using a PEM public key"
          );
        }
        const cacheKey = `${publicKeyValue}\0${algValue}`;
        if (!_pemKeyCache.has(cacheKey)) {
          _pemKeyCache.set(cacheKey, importSPKI(publicKeyValue, algValue));
        }
        const importedKey = await _pemKeyCache.get(cacheKey)!;
        const result = await jwtVerify(jwt, importedKey, { clockTolerance });
        payload = result.payload;
        header = result.protectedHeader;
      } else if ('keys' in publicKeyValue && Array.isArray((publicKeyValue as any).keys)) {
        // Inline JWK Set — createLocalJWKSet handles key selection by kid/alg.
        // createLocalJWKSet is synchronous so we cache the returned function directly.
        if (!_jwkSetFnCache.has(publicKeyValue)) {
          _jwkSetFnCache.set(publicKeyValue, createLocalJWKSet(publicKeyValue as JSONWebKeySet));
        }
        const keySet = _jwkSetFnCache.get(publicKeyValue)!;
        const result = await jwtVerify(jwt, keySet, { clockTolerance });
        payload = result.payload;
        header = result.protectedHeader;
      } else {
        // Single JWK — alg comes from the JWK's own `alg` field or algValue.
        // Reject symmetric JWKs (kty: "oct") before importing: a symmetric key passed
        // as publicKey violates the option's asymmetric-only contract and would result
        // in a confusing jose error rather than a clear configuration error.
        if (!_jwkKeyCache.has(publicKeyValue)) {
          _jwkKeyCache.set(publicKeyValue, (async () => {
            if ((publicKeyValue as JWK).kty === 'oct') {
              throw new InvalidRequestError(
                "'publicKey' must be an asymmetric key (RSA, EC, OKP). Use 'secret' for symmetric verification."
              );
            }
            const importedKey = await importJWK(publicKeyValue as JWK, algValue);
            return importedKey as KeyLike;
          })());
        }
        const importedKey = await _jwkKeyCache.get(publicKeyValue)!;
        const result = await jwtVerify(jwt, importedKey, { clockTolerance });
        payload = result.payload;
        header = result.protectedHeader;
      }
    } else if (jwksUriValue) {
      // Asymmetric algorithm verification via remote JWKS (RS256, ES256, PS256, etc.)
      // These use public/private key pairs. We fetch the public keys from the JWKS endpoint
      // and use them to verify the signature. The getKeyFnGetter handles JWKS caching.
      const result = await jwtVerify(jwt, getKeyFnGetter(jwksUriValue), {
        clockTolerance,
      });
      payload = result.payload;
      header = result.protectedHeader;
    } else {
      // This should never happen if configuration is valid, but we check defensively
      throw new InvalidTokenError('No JWKS URI, public key, or secret available for verification');
    }

    // Validate claims: Check all JWT claims (iss, aud, exp, custom claims, etc.)
    // against the configured validators. Throws if any validation fails.
    await validate(payload, header, validators);

    return { payload, header, token: jwt };
  };

  return async (jwt: string, requestContext?: RequestContext) => {
    let allowedSigningAlgs: string[] | undefined;

    try {
      // MCD Mode: Handle multiple issuers
      if (mcd) {
        // STEP 1: Decode token (unverified) to extract issuer claim and algorithm
        const unverifiedPayload = decodeJwt(jwt);
        const tokenIssuer = unverifiedPayload.iss;

        if (!tokenIssuer) {
          throw new InvalidTokenError("Token missing required 'iss' claim");
        }

        const normalizedTokenIssuer = normalizeIssuerUrl(tokenIssuer);

        // STEP 2: Resolve issuers (static or dynamic)
        let resolvedIssuers: (string | IssuerConfig)[];

        if (typeof mcd.issuers === 'function') {
          // Dynamic resolver with real request context
          const context: IssuerResolverContext = {
            url: requestContext?.url
              ? new URL(requestContext.url)
              : new URL('http://localhost'),
            headers: requestContext?.headers || {},
          };
          const result = await mcd.issuers(context);

          if (!Array.isArray(result)) {
            throw new InvalidRequestError('Issuer resolver function must return an array');
          }

          resolvedIssuers = result;
        } else {
          resolvedIssuers = Array.isArray(mcd.issuers)
            ? mcd.issuers
            : [mcd.issuers];
        }

        if (resolvedIssuers.length === 0) {
          throw new InvalidTokenError('No issuers configured for token validation');
        }

        // STEP 3: Normalize and match issuer
        const normalizedConfigs = resolvedIssuers.map(normalizeIssuerConfig);
        const matchedConfig = normalizedConfigs.find(
          (config) => config.issuer === normalizedTokenIssuer
        );

        if (!matchedConfig) {
          throw new InvalidTokenError('Token issuer is not allowed');
        }

        // STEP 3a: Validate resolver-returned config is internally consistent.
        // Dynamic resolvers bypass the upfront static-config checks, so we apply
        // the same alg/secret consistency rules here at verification time.
        // These checks run BEFORE validateAlgorithmEarly so that conflicts like
        // publicKey+secret are reported with a clear error before algorithm checks.
        const hasSecret = 'secret' in matchedConfig && matchedConfig.secret;
        const hasPublicKey = 'publicKey' in matchedConfig &&
          !!(matchedConfig as AsymmetricIssuerConfig).publicKey;
        const configAlg = matchedConfig.alg;

        if (hasPublicKey && hasSecret) {
          throw new InvalidTokenError(
            `Issuer provides both 'publicKey' and 'secret'. These are mutually exclusive.`
          );
        }
        if (hasPublicKey && 'jwksUri' in matchedConfig && (matchedConfig as AsymmetricIssuerConfig).jwksUri) {
          throw new InvalidTokenError(
            `Issuer provides both 'publicKey' and 'jwksUri'. These are mutually exclusive.`
          );
        }
        if (configAlg && SYMMETRIC_ALGS.includes(configAlg) && !hasSecret) {
          throw new InvalidTokenError(
            `Issuer specifies symmetric algorithm but no secret provided`
          );
        }
        if (hasSecret && configAlg && ASYMMETRIC_ALGS.includes(configAlg)) {
          throw new InvalidTokenError(
            `Issuer provides a secret but specifies asymmetric algorithm `
          );
        }
        if (hasSecret && !configAlg) {
          throw new InvalidTokenError(
            `Issuer provides a secret but no 'alg' specified`
          );
        }

        // STEP 3b: Reject symmetric algorithms if no secret configured
        // This prevents SSRF attacks by ensuring we never fetch JWKS for symmetric tokens
        validateAlgorithmEarly(jwt, !!hasSecret);

        // STEP 4: Get JWKS URI and configure verification
        let finalJwksUri: string | undefined;
        let finalSecret: string | undefined;
        let finalPublicKey: PublicKeyInput | undefined;
        let finalAlg: string | undefined;

        if (hasSecret) {
          // Symmetric algorithm
          finalSecret = (matchedConfig as SymmetricIssuerConfig).secret;
          finalAlg = matchedConfig.alg;
        } else {
          // Asymmetric algorithm
          finalAlg = (matchedConfig as AsymmetricIssuerConfig).alg;

          if (hasPublicKey) {
            // Static public key provided — no discovery or remote JWKS needed
            finalPublicKey = (matchedConfig as AsymmetricIssuerConfig).publicKey;
          } else if ((matchedConfig as AsymmetricIssuerConfig).jwksUri) {
            // Custom JWKS URI provided
            finalJwksUri = (matchedConfig as AsymmetricIssuerConfig).jwksUri;
          } else {
            // Perform discovery
            const {
              jwks_uri: discoveredJwksUri,
              issuer: discoveredIssuer,
              id_token_signing_alg_values_supported: idTokenSigningAlgValuesSupported,
            } = await getDiscovery(tokenIssuer);

            // STEP 4a: Double-validate that discovery metadata's issuer matches token's iss
            // Normalize both sides to handle trailing slash differences
            if (normalizeIssuerUrl(discoveredIssuer) !== normalizedTokenIssuer) {
              throw new InvalidTokenError(
                'Discovery metadata issuer does not match token issuer'
              );
            }

            finalJwksUri = discoveredJwksUri;
            issuer = discoveredIssuer;
            allowedSigningAlgs = idTokenSigningAlgValuesSupported;
          }
        }

        // STEP 5-7: Verify signature and validate claims
        // Now that we've identified the correct issuer config and obtained the JWKS URI,
        // static public key (or secret), we can verify the JWT signature and validate all claims.
        // Note: We use the original token issuer (not normalized) for validation to
        // ensure the 'iss' claim check matches exactly what's in the token.
        return await verifyAndValidateJwt(
          jwt,
          tokenIssuer, // Original issuer from token (not normalized)
          finalJwksUri,
          finalSecret,
          finalPublicKey,
          finalAlg,
          allowedSigningAlgs
        );
      }

      // Single Issuer Mode with Discovery
      if (issuerBaseURL) {
        //early validation
        validateAlgorithmEarly(jwt, !!secret);

        const {
          jwks_uri: discoveredJwksUri,
          issuer: discoveredIssuer,
          id_token_signing_alg_values_supported: idTokenSigningAlgValuesSupported,
        } = await getDiscovery(issuerBaseURL);

        jwksUri = jwksUri || discoveredJwksUri;
        issuer = issuer || discoveredIssuer;
        allowedSigningAlgs = idTokenSigningAlgValuesSupported;
      }

      // For non-discovery paths (publicKey or jwksUri without issuerBaseURL), run early
      // algorithm validation so that tokens with the wrong alg (e.g. "HS256" or "none")
      // produce a clear SDK error rather than a confusing jose internal error.
      // The issuerBaseURL path already calls validateAlgorithmEarly inside its own block
      // above; MCD mode calls it during issuer matching (STEP 3b).
      if (!issuerBaseURL && publicKey) {
        validateAlgorithmEarly(jwt, false);
      }

      // Verify signature and validate claims for single issuer mode
      // At this point we have everything we need: the issuer, JWKS URI, static public key
      // (or secret), and algorithm configuration. The helper handles the actual signature
      // verification and claim validation using the same logic as MCD mode.
      return await verifyAndValidateJwt(
        jwt,
        issuer,
        jwksUri,
        secret,
        publicKey,
        tokenSigningAlg,
        allowedSigningAlgs
      );
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;

export { JWTPayload, JWSHeaderParameters };
