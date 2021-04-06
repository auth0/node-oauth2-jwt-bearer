import SignJWT from 'jose/jwt/sign';
import { generateKeyPair } from 'jose/util/generate_key_pair';
import { fromKeyLike } from 'jose/jwk/from_key_like';
import nock = require('nock');
import { tokenVerifier } from '../src';

const now = (Date.now() / 1000) | 0;
const day = 60 * 60 * 24;

interface CreateJWTOptions {
  payload?: { [key: string]: any };
  issuer?: string;
  subject?: string;
  audience?: string;
  kid?: string;
  iat?: number;
  exp?: number;
}

const createJwt = async ({
  payload = {},
  issuer = 'https://issuer.example.com/',
  subject = 'me',
  audience = 'https://api/',
  iat = now,
  exp = now + day,
  kid = 'kid',
}: CreateJWTOptions): Promise<string> => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const publicJwk = await fromKeyLike(publicKey);
  nock(issuer)
    .get('/.well-known/jwks.json')
    .once()
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

describe('token-verifier', () => {
  it('should verify the token', async () => {
    const jwt = await createJwt({});

    const verify = tokenVerifier({
      jwksUri: 'https://issuer.example.com/.well-known/jwks.json',
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
    });
    await expect(verify(jwt)).resolves.toMatchObject({
      iss: 'https://issuer.example.com/',
      sub: 'me',
      aud: 'https://api/',
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
  });
});
