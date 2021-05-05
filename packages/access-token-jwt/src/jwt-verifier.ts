import { strict as assert } from 'assert';
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
      origJWKS = createRemoteJWKSet(new URL(jwksUri));
    }
    return origJWKS(...args);
  };

  return async (jwt: string) => {
    try {
      if (!jwksUri) {
        discovery = discovery || discover(issuerBaseURL);
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
