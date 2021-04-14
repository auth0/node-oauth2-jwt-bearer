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
  let _JWKS: GetKeyFn;
  const JWKS = async (...args: Parameters<GetKeyFn>) => {
    if (!_JWKS) {
      if (!jwksUri) {
        ({ jwks_uri: jwksUri, issuer } = await discover(issuerBaseURL));
      }
      _JWKS = createRemoteJWKSet(new URL(jwksUri));
    }
    return _JWKS(...args);
  };

  return async (jwt: string) => {
    try {
      const { payload } = await jwtVerify(jwt, JWKS, {
        issuer: issuer || issuerBaseURL,
        audience,
      });
      return payload;
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  };
};

export default jwtVerifier;
