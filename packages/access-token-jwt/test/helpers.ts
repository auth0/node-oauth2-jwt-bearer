import { Buffer } from 'buffer';
import { createSecretKey } from 'crypto';
import { SignJWT, generateKeyPair, exportJWK, exportSPKI } from 'jose';
import type { JWK, JSONWebKeySet } from 'jose';
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
}: CreateJWTOptions = {}): Promise<string> => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
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

  const secretKey = secret && createSecretKey(Buffer.from(secret));

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
    .sign(secretKey || privateKey);
};

export interface CreateJwtWithKeyResult {
  jwt: string;
  publicKeyJwk: JWK;
  publicKeyJwkSet: JSONWebKeySet;
  publicKeyPem: string;
}

/**
 * Create a JWT signed with a freshly generated RS256 key pair and return the
 * signed token together with the public key in several formats (JWK, JWK Set,
 * PEM SPKI) so tests can exercise the `publicKey` option without needing a
 * running JWKS endpoint.
 */
export const createJwtWithKey = async ({
  payload = {},
  issuer = 'https://issuer.example.com/',
  subject = 'me',
  audience = 'https://api/',
  iat = now,
  exp = now + 60 * 60 * 24,
  kid = 'kid',
}: Omit<CreateJWTOptions, 'jwksUri' | 'discoveryUri' | 'jwksSpy' | 'discoverSpy' | 'delay' | 'secret'> = {}): Promise<CreateJwtWithKeyResult> => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const publicKeyPem = await exportSPKI(publicKey);
  const publicKeyJwk: JWK = { ...jwk, kid, alg: 'RS256' };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid })
    .setIssuer(issuer)
    .setSubject(subject)
    .setAudience(audience)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(privateKey);

  return {
    jwt,
    publicKeyJwk,
    publicKeyJwkSet: { keys: [publicKeyJwk] },
    publicKeyPem,
  };
};
