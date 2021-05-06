import { strict as assert } from 'assert';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { URL } from 'url';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload } from 'jose/jwt/verify';
import { InvalidTokenError } from 'oauth2-bearer';
import discover, { IssuerMetadata } from './discovery';
import validate, { defaultValidators, Validators } from './validate';

interface JwtVerifierOptions {
  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   */
  audience: string | string[];

  /**
   * An instance of http.Agent or https.Agent to pass to the http.get or https.get method options. Use when behind an http(s) proxy.
   */
  agent?: HttpAgent | HttpsAgent;

  /**
   * Duration in ms for which no more HTTP requests to the JWKS Uri endpoint will be triggered after a previous successful fetch.
   * Default is 30000.
   */
  cooldownDuration?: number;

  /**
   * Timeout in ms for the HTTP request. When reached the request will be aborted and the verification will fail.
   * Default is 5000.
   */
  timeoutDuration?: number;

  validators?: Partial<Validators>;

  clockTolerance?: number;

  maxTokenAge?: number;

  strict?: boolean;
}

export interface WithDiscovery extends JwtVerifierOptions {
  /**
   *
   */
  issuerBaseURL: string;
}

export interface WithoutDiscovery extends JwtVerifierOptions {
  /**
   * Expected JWT "iss" (Issuer) Claim value.
   */
  issuer: string;

  /**
   *
   */
  jwksUri: string;
}

export type VerifyJwt = (jwt: string) => Promise<{ payload: JWTPayload }>;

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
      return { payload };
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;
