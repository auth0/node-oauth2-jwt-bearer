import { strict as assert } from 'assert';
import { URL } from 'url';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload } from 'jose/jwt/verify';
import { InvalidTokenError } from 'oauth2-bearer';
import discover from './discovery';

interface JwtVerifierOptions {
  /**
   * Expected JWT "iss" (Issuer) Claim value(s).
   */
  issuer?: string | string[];

  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   */
  audience: string | string[];
}

export interface WithDiscovery extends JwtVerifierOptions {
  /**
   *
   */
  issuerBaseURL: string;
}

export interface WithoutDiscovery extends JwtVerifierOptions {
  /**
   * Expected JWT "iss" (Issuer) Claim value(s).
   */
  issuer: string | string[];

  /**
   *
   */
  jwksUri: string;
}

export type VerifyJwt = (jwt: string) => Promise<JWTPayload>;

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
}: any): VerifyJwt => {
  let origJWKS: GetKeyFn;
  let discoveredIssuer: string;

  assert(
    (issuer && jwksUri) || issuerBaseURL,
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
        ({ jwks_uri: jwksUri, issuer: discoveredIssuer } = await discover(
          issuerBaseURL
        ));
      }
      const { payload } = await jwtVerify(jwt, JWKS, {
        issuer: issuer || discoveredIssuer,
        audience,
      });
      return payload;
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;
