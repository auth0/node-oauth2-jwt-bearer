import { strict as assert } from 'assert';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { URL } from 'url';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload, JWSHeaderParameters } from 'jose/jwt/verify';
import { InvalidTokenError } from 'oauth2-bearer';
import discover, { IssuerMetadata } from './discovery';
import validate, { defaultValidators, Validators } from './validate';

interface JwtVerifierOptions {
  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   */
  audience: string | string[];

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
   * Timeout in ms for the HTTP request. When reached the request will be
   * aborted.
   * Default is 5000.
   */
  timeoutDuration?: number;

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
   *      // implements {@Link FunctionValidator}}
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
   * Maximum age (in secs) from when a token was issued to when it con no longer
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
}

export interface WithDiscovery extends JwtVerifierOptions {
  /**
   * Base url, used to find the authorization server's app metadata per
   * https://datatracker.ietf.org/doc/html/rfc8414
   * You can pass a full url including `.well-known` if your discovery lives at
   * a non standard path.
   */
  issuerBaseURL: string;
}

export interface WithoutDiscovery extends JwtVerifierOptions {
  /**
   * Expected JWT "iss" (Issuer) Claim value.
   */
  issuer: string;

  /**
   * Url for the authorization server's JWKS to find the public key to verify
   * an Access Token JWT.
   */
  jwksUri: string;
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

export type VerifyJwt = (jwt: string) => Promise<VerifyJwtResult>;

type GetKeyFn = ReturnType<typeof createRemoteJWKSet>;

export interface JwtVerifier {
  (opts: WithDiscovery): VerifyJwt;
  (opts: WithoutDiscovery): VerifyJwt;
}

const jwtVerifier: JwtVerifier = ({
  issuerBaseURL,
  jwksUri,
  issuer,
  audience,
  agent,
  cooldownDuration = 30000,
  timeoutDuration = 5000,
  clockTolerance = 5,
  maxTokenAge,
  strict = false,
  validators: customValidators,
}: any): VerifyJwt => {
  let origJWKS: GetKeyFn;
  let discovery: Promise<IssuerMetadata>;
  let validators: Validators;

  assert(
    (issuerBaseURL && !(issuer || jwksUri)) ||
      (!issuerBaseURL && issuer && jwksUri),
    'You must provide an "issuerBaseURL" or an "issuer" and "jwksUri"'
  );
  assert(audience, 'An "audience" is required to validate the "aud" claim');

  const JWKS = async (...args: Parameters<GetKeyFn>) => {
    if (!origJWKS) {
      origJWKS = createRemoteJWKSet(new URL(jwksUri), {
        agent,
        cooldownDuration,
        timeoutDuration,
      });
    }
    return origJWKS(...args);
  };

  return async (jwt: string) => {
    try {
      if (!jwksUri) {
        discovery =
          discovery || discover(issuerBaseURL, { agent, timeoutDuration });
        ({ jwks_uri: jwksUri, issuer } = await discovery);
      }
      validators ||= {
        ...defaultValidators(
          issuer,
          audience,
          clockTolerance,
          maxTokenAge,
          strict
        ),
        ...customValidators,
      };
      const { payload, protectedHeader: header } = await jwtVerify(jwt, JWKS);
      await validate(payload, header, validators);
      return { payload, header, token: jwt };
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;

export { JWTPayload, JWSHeaderParameters };
