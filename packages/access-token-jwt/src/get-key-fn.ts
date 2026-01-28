import { createSecretKey } from 'crypto';
import { createRemoteJWKSet } from 'jose';
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
  // Support multiple issuers by caching getKeyFn per jwksUri
  const keyFnCache = new Map<string, GetKeyFn>();

  const secretKey = secret && createSecretKey(Buffer.from(secret));

  return (jwksUri: string) => {
    if (secretKey) return () => secretKey;

    // Check if we have a cached getKeyFn for this jwksUri
    let getKeyFn = keyFnCache.get(jwksUri);

    if (!getKeyFn) {
      // Create new getKeyFn for this jwksUri and cache it
      getKeyFn = createRemoteJWKSet(new URL(jwksUri), {
        agent,
        cooldownDuration,
        timeoutDuration,
        cacheMaxAge,
      });
      keyFnCache.set(jwksUri, getKeyFn);
    }

    return getKeyFn;
  };
};
