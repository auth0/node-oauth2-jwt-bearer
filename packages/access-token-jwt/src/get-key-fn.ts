import { createSecretKey } from 'crypto';
import { createRemoteJWKSet, KeyLike } from 'jose';
import { JwtVerifierOptions } from './jwt-verifier';

type GetKeyFn = ReturnType<typeof createRemoteJWKSet>;

export type JWKSOptions = Required<
  Pick<
    JwtVerifierOptions,
    'cooldownDuration' | 'timeoutDuration' | 'cacheMaxAge'
  >
> &
  Pick<JwtVerifierOptions, 'agent' | 'secret'>;

export default ({
  agent,
  cooldownDuration,
  timeoutDuration,
  cacheMaxAge,
  secret
}: JWKSOptions) => {
  let getKeyFn: GetKeyFn;
  let prevjwksUri: string;

  // If secret is a KeyLike object (public key), use it directly
  if (secret && typeof secret !== 'string') {
    const publicKey = secret as KeyLike;
    return () => () => publicKey;
  }

  // Otherwise, handle string secret as before
  const secretKey = typeof secret === 'string' && secret 
    ? createSecretKey(Buffer.from(secret)) 
    : undefined;

  return (jwksUri: string) => {
    if (secretKey) return () => secretKey;
    if (!getKeyFn || prevjwksUri !== jwksUri) {
      prevjwksUri = jwksUri;
      getKeyFn = createRemoteJWKSet(new URL(jwksUri), {
        agent,
        cooldownDuration,
        timeoutDuration,
        cacheMaxAge,
      });
    }
    return getKeyFn;
  };
};
