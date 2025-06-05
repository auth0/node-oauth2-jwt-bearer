import { exportJWK, generateKeyPair } from 'jose';
import nock from 'nock';
import { jwtVerifier } from '../src';
import { createJwt } from './helpers';

describe('public-key verification', () => {
  beforeEach(() => {
    nock.cleanAll();
  });

  it('should verify a token with a directly provided public key', async () => {
    // Generate a key pair for testing
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    
    // Create a JWT signed with the private key
    const tokenPayload = { foo: 'bar' };
    const jwt = await createJwt({
      payload: tokenPayload,
      privateKey: privateKey
    });

    // Verify the JWT using the public key directly
    const verify = jwtVerifier({
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
      secret: publicKey
    });
    
    const result = await verify(jwt);
    expect(result.payload.foo).toBe('bar');
  });

  it('should verify a token with directly provided public key when tokenSigningAlg is specified', async () => {
    // Generate a key pair for testing
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    
    // Create a JWT signed with the private key
    const tokenPayload = { foo: 'bar' };
    const jwt = await createJwt({
      payload: tokenPayload,
      privateKey: privateKey
    });

    // Verify the JWT using the public key directly with explicit alg
    const verify = jwtVerifier({
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
      secret: publicKey,
      tokenSigningAlg: 'RS256'
    });
    
    const result = await verify(jwt);
    expect(result.payload.foo).toBe('bar');
  });

  it('should fail to verify when using mismatched keys', async () => {
    // Generate two different key pairs
    const keyPair1 = await generateKeyPair('RS256');
    const keyPair2 = await generateKeyPair('RS256');
    
    // Create JWT with first private key
    const jwt = await createJwt({
      payload: { test: 'data' },
      privateKey: keyPair1.privateKey
    });

    // Try to verify with second key's public key (should fail)
    const verify = jwtVerifier({
      issuer: 'https://issuer.example.com/',
      audience: 'https://api/',
      secret: keyPair2.publicKey
    });
    
    await expect(verify(jwt)).rejects.toThrow();
  });
});
