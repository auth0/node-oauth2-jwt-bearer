import { strict as assert } from 'assert';
import { TextEncoder } from 'util';
import { Buffer } from 'buffer';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { jwtVerify, decodeJwt } from 'jose';
import type { JWTPayload, JWSHeaderParameters } from 'jose';
import { InvalidTokenError } from 'oauth2-bearer';
import discovery from './discovery';
import getKeyFn from './get-key-fn';
import validate, { defaultValidators, Validators } from './validate';

// MCD Types
export interface AsymmetricIssuerConfig {
  issuer: string;
  alg?: string;
  jwksUri?: string;
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
  tokenClaims?: { iss?: string; aud?: string | string[]; [key: string]: unknown };
}

export type IssuerResolverResult = string | string[] | IssuerConfig[];

export type IssuerResolverFunction = (
  context: IssuerResolverContext
) => Promise<IssuerResolverResult> | IssuerResolverResult;

export interface Auth0MCDOptions {
  issuers: string | string[] | IssuerConfig[] | IssuerResolverFunction;
  cacheTTL?: number;
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
   */
  cacheMaxAge?: number;

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
  auth0MCD?: Auth0MCDOptions;
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
  tokenSigningAlg = process.env.TOKEN_SIGNING_ALG as string,
  auth0MCD,
  agent,
  cooldownDuration = 30000,
  timeoutDuration = 5000,
  cacheMaxAge = 600000,
  clockTolerance = 5,
  maxTokenAge,
  strict = false,
  validators: customValidators,
}: JwtVerifierOptions): VerifyJwt => {
  let validators: Validators;
  let allowedSigningAlgs: string[] | undefined;

  // Validation: Ensure proper configuration
  assert(
    auth0MCD || issuerBaseURL || (issuer && (jwksUri || secret)),
    "You must provide 'auth0MCD', 'issuerBaseURL', or both 'issuer' and ('jwksUri' or 'secret')"
  );
  assert(
    !(auth0MCD && issuerBaseURL),
    "You must not provide both 'auth0MCD' and 'issuerBaseURL'"
  );
  assert(
    !(secret && jwksUri),
    "You must not provide both a 'secret' and 'jwksUri'"
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

  // MCD Support: Validate auth0MCD configuration
  if (auth0MCD) {
    assert(auth0MCD.issuers, "Invalid MCD configuration: 'issuers' is required");
  }

  const getDiscovery = discovery({
    agent,
    timeoutDuration,
    cacheMaxAge,
  });

  const getKeyFnGetter = getKeyFn({
    agent,
    cooldownDuration,
    timeoutDuration,
    cacheMaxAge,
    secret,
  });

  // Helper: Normalize issuer URL
  const normalizeIssuerUrl = (url: string): string => {
    try {
      const parsed = new URL(url);
      // Lowercase hostname, remove default ports, ensure no trailing slash
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
    } catch {
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

  return async (jwt: string, requestContext?: RequestContext) => {
    try {
      // MCD Mode: Handle multiple issuers
      if (auth0MCD) {
        // STEP 1: Decode token (unverified) to extract issuer claim and algorithm
        const unverifiedPayload = decodeJwt(jwt);
        const tokenIssuer = unverifiedPayload.iss;

        if (!tokenIssuer) {
          throw new Error("Token missing required 'iss' claim");
        }

        const normalizedTokenIssuer = normalizeIssuerUrl(tokenIssuer);

        // STEP 2: Resolve issuers (static or dynamic)
        let resolvedIssuers: (string | IssuerConfig)[];

        if (typeof auth0MCD.issuers === 'function') {
          // Dynamic resolver with real request context
          const context: IssuerResolverContext = {
            url: requestContext?.url
              ? new URL(requestContext.url)
              : new URL('http://localhost'),
            headers: requestContext?.headers || {},
            tokenClaims: unverifiedPayload,
          };
          const result = await auth0MCD.issuers(context);
          resolvedIssuers = Array.isArray(result) ? result : [result];
        } else {
          // Static configuration
          resolvedIssuers = Array.isArray(auth0MCD.issuers)
            ? auth0MCD.issuers
            : [auth0MCD.issuers];
        }

        // STEP 3: Normalize and match issuer
        const normalizedConfigs = resolvedIssuers.map(normalizeIssuerConfig);
        const matchedConfig = normalizedConfigs.find(
          (config) => config.issuer === normalizedTokenIssuer
        );

        if (!matchedConfig) {
          throw new Error(`Issuer '${tokenIssuer}' is not allowed`);
        }

        // STEP 3a: Reject symmetric algorithms if no secret configured
        // This prevents SSRF attacks by ensuring we never fetch JWKS for symmetric tokens
        const hasSecret = 'secret' in matchedConfig && matchedConfig.secret;
        if (!hasSecret) {
          const { alg } = JSON.parse(
            Buffer.from(jwt.split('.')[0], 'base64').toString()
          );
          if (alg && typeof alg === 'string' && alg.startsWith('HS')) {
            throw new Error(
              'Symmetric algorithms (HS256, HS384, HS512) are not supported for JWKS-based verification. Configure a secret if you want to verify symmetric tokens.'
            );
          }
        }

        // STEP 4: Get JWKS URI and configure verification
        let finalJwksUri: string | undefined;
        let finalSecret: string | undefined;
        let finalAlg: string | undefined;

        if (hasSecret) {
          // Symmetric algorithm
          finalSecret = (matchedConfig as SymmetricIssuerConfig).secret;
          finalAlg = matchedConfig.alg;
        } else {
          // Asymmetric algorithm
          finalAlg = (matchedConfig as AsymmetricIssuerConfig).alg;

          if ((matchedConfig as AsymmetricIssuerConfig).jwksUri) {
            // Custom JWKS URI provided
            finalJwksUri = (matchedConfig as AsymmetricIssuerConfig).jwksUri;
          } else {
            // Perform discovery
            const {
              jwks_uri: discoveredJwksUri,
              issuer: discoveredIssuer,
              id_token_signing_alg_values_supported:
                idTokenSigningAlgValuesSupported,
            } = await getDiscovery(tokenIssuer);

            // STEP 4a: Double-validate that discovery metadata's issuer matches token's iss
            if (discoveredIssuer !== tokenIssuer) {
              throw new Error(
                `Discovery metadata issuer '${discoveredIssuer}' does not match token issuer '${tokenIssuer}'`
              );
            }

            finalJwksUri = discoveredJwksUri;
            issuer = discoveredIssuer;
            allowedSigningAlgs = idTokenSigningAlgValuesSupported;
          }
        }

        // STEP 5: Setup validators
        validators ||= {
          ...defaultValidators(
            tokenIssuer, // Use original issuer for validation, not normalized
            audience,
            clockTolerance,
            maxTokenAge,
            strict,
            allowedSigningAlgs,
            finalAlg
          ),
          ...customValidators,
        };

        // STEP 6: Verify JWT
        let payload: JWTPayload;
        let header: JWSHeaderParameters;

        if (finalSecret) {
          const keyFn = new TextEncoder().encode(finalSecret);
          const result = await jwtVerify(jwt, keyFn, { clockTolerance });
          payload = result.payload;
          header = result.protectedHeader;
        } else if (finalJwksUri) {
          const result = await jwtVerify(jwt, getKeyFnGetter(finalJwksUri), {
            clockTolerance,
          });
          payload = result.payload;
          header = result.protectedHeader;
        } else {
          throw new Error('No JWKS URI or secret available for verification');
        }

        // STEP 7: Validate claims
        await validate(payload, header, validators);

        return { payload, header, token: jwt };
      }

      // Single Issuer Mode with Discovery
      if (issuerBaseURL) {
        const {
          jwks_uri: discoveredJwksUri,
          issuer: discoveredIssuer,
          id_token_signing_alg_values_supported:
            idTokenSigningAlgValuesSupported,
        } = await getDiscovery(issuerBaseURL);
        jwksUri = jwksUri || discoveredJwksUri;
        issuer = issuer || discoveredIssuer;
        allowedSigningAlgs = idTokenSigningAlgValuesSupported;
      }

      // Setup validators for single issuer
      validators ||= {
        ...defaultValidators(
          issuer,
          audience,
          clockTolerance,
          maxTokenAge,
          strict,
          allowedSigningAlgs,
          tokenSigningAlg
        ),
        ...customValidators,
      };

      // Verify JWT with single issuer config
      const { payload, protectedHeader: header } = await jwtVerify(
        jwt,
        getKeyFnGetter(jwksUri),
        { clockTolerance }
      );

      // Validate claims
      await validate(payload, header, validators);

      return { payload, header, token: jwt };
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;

export { JWTPayload, JWSHeaderParameters };
