import { URL } from 'url';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload } from 'jose/jwt/verify';
import { InvalidTokenError } from 'oauth2-bearer';
import discover, { IssuerMetadata } from './discovery';

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
  let discovery: Promise<IssuerMetadata>;

  if (!jwksUri) {
    discovery = discover(issuerBaseURL);
  }

  const JWKS = async (...args: Parameters<GetKeyFn>) => {
    if (!_JWKS) {
      _JWKS = createRemoteJWKSet(new URL(jwksUri));
    }
    return _JWKS(...args);
  };

  return async (jwt: string) => {
    let discoveredIssuer;
    try {
      if (discovery) {
        ({ jwks_uri: jwksUri, issuer: discoveredIssuer } = await discovery);
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
