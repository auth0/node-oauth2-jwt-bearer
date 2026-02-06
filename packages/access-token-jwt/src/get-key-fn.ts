import { createSecretKey } from 'crypto';
import { createRemoteJWKSet } from 'jose';
import { JwtVerifierOptions } from './jwt-verifier';
import { LRUCache } from './lru-cache';

type GetKeyFn = ReturnType<typeof createRemoteJWKSet>;

export type JWKSOptions = Required<
  Pick<
    JwtVerifierOptions,
    'cooldownDuration' | 'timeoutDuration' | 'cacheMaxAge'
  >
> &
  Pick<JwtVerifierOptions, 'agent' | 'secret' | 'cache'>;

export default ({
  agent,
  cooldownDuration,
  timeoutDuration,
  cacheMaxAge,
  secret,
  cache
}: JWKSOptions) => {
  // Create LRU cache for JWKS key functions
  // Use cache.jwks options if provided, otherwise fall back to cacheMaxAge (deprecated)
  // Note: Each cached GetKeyFn has its own internal JWKS caching via jose library
  const cacheOptions = {
    maxEntries: cache?.jwks?.maxEntries ?? 100,
    // Note: cacheMaxAge is always defined (has default value), so final fallback never reached
    ttl: /* istanbul ignore next */ cache?.jwks?.ttl ?? cacheMaxAge ?? 600000,
  };

  const keyFnCache = new LRUCache<GetKeyFn>(cacheOptions);

  const secretKey = secret && createSecretKey(Buffer.from(secret));

  return (jwksUri: string) => {
    if (secretKey) return () => secretKey;

    // Check if we have a cached getKeyFn for this jwksUri
    let getKeyFn = keyFnCache.get(jwksUri);

    if (!getKeyFn) {
      // Create new getKeyFn for this jwksUri and cache it
      // jose's createRemoteJWKSet handles JWKS fetching and internal caching
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
