import SignJWT from 'jose/jwt/sign';
import { generateKeyPair } from 'jose/util/generate_key_pair';
import { fromKeyLike } from 'jose/jwk/from_key_like';
import nock = require('nock');

export const now = (Date.now() / 1000) | 0;
const day = 60 * 60 * 24;

interface CreateJWTOptions {
  payload?: { [key: string]: any };
  issuer?: string;
  subject?: string;
  audience?: string;
  jwksUri?: string;
  kid?: string;
  iat?: number;
  exp?: number;
}

export const createJwt = async ({
  payload = {},
  issuer = 'https://issuer.example.com/',
  subject = 'me',
  audience = 'https://api/',
  jwksUri = '/.well-known/jwks.json',
  iat = now,
  exp = now + day,
  kid = 'kid',
}: CreateJWTOptions = {}): Promise<string> => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const publicJwk = await fromKeyLike(publicKey);
  nock(issuer)
    .get(jwksUri)
    .reply(200, { keys: [{ kid: 'kid', ...publicJwk }] });

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
      kid,
    })
    .setIssuer(issuer)
    .setSubject(subject)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(privateKey);
};
