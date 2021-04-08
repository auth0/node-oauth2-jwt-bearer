import { URL } from 'url';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload } from 'jose/jwt/verify';

export interface TokenVerifierOptions {
  /**
   * Uri for the JWKS endpoint.
   * TODO: this will be optional when we add discovery.
   */
  jwksUri: string;

  /**
   * Expected JWT "iss" (Issuer) Claim value(s).
   */
  issuer: string | string[];

  /**
   * Expected JWT "aud" (Audience) Claim value(s).
   */
  audience: string | string[];
}

export type VerifyJwt = (jwt: string) => Promise<JWTPayload>;

export default ({
  jwksUri,
  issuer,
  audience,
}: TokenVerifierOptions): VerifyJwt => {
  const JWKS = createRemoteJWKSet(new URL(jwksUri));
  return async (jwt: string) => {
    const { payload } = await jwtVerify(jwt, JWKS, {
      issuer,
      audience,
    });
    return payload;
  };
};
