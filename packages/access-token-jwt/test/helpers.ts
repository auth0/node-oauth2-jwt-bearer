import { Buffer } from 'buffer';
import { createSecretKey } from 'crypto';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import nock = require('nock');

export const now = (Date.now() / 1000) | 0;
const day = 60 * 60 * 24;

interface CreateJWTOptions {
  payload?: { [key: string]: any };
  issuer?: string;
  subject?: string;
  audience?: string;
  jwksUri?: string;
  discoveryUri?: string;
  kid?: string;
  iat?: number;
  exp?: number;
  jwksSpy?: jest.Mock;
  discoverSpy?: jest.Mock;
  delay?: number;
  secret?: string;
  privateKey?: any; // Allow passing a specific private key
}

export const createJwt = async ({
  payload = {},
  issuer = 'https://issuer.example.com/',
  subject = 'me',
  audience = 'https://api/',
  jwksUri = '/.well-known/jwks.json',
  discoveryUri = '/.well-known/openid-configuration',
  iat = now,
  exp = now + day,
  kid = 'kid',
  jwksSpy = jest.fn(),
  discoverSpy = jest.fn(),
  secret,
  privateKey: customPrivateKey,
}: CreateJWTOptions = {}): Promise<string> => {
  // Generate key pair if not provided
  const { publicKey, privateKey: generatedPrivateKey } = customPrivateKey 
    ? { publicKey: null, privateKey: customPrivateKey } 
    : await generateKeyPair('RS256');
    
  const finalPrivateKey = customPrivateKey || generatedPrivateKey;
  
  // Only set up mocks if not using custom keys
  if (!customPrivateKey) {
    const publicJwk = await exportJWK(publicKey);
    nock(issuer)
      .persist()
      .get(jwksUri)
      .reply(200, (...args) => {
        jwksSpy(...args);
        return { keys: [{ kid, ...publicJwk }] };
      })
      .get(discoveryUri)
      .reply(200, (...args) => {
        discoverSpy(...args);
        return {
          issuer,
          jwks_uri: (issuer + jwksUri).replace('//.well-known', '/.well-known'),
        };
      });
  }

  const secretKey = secret && createSecretKey(Buffer.from(secret));
  const signingKey = secretKey || finalPrivateKey;

  return new SignJWT(payload)
    .setProtectedHeader({
      alg: secretKey ? 'HS256' : 'RS256',
      typ: 'JWT',
      kid,
    })
    .setIssuer(issuer)
    .setSubject(subject)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(signingKey);
};
