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
  let getKeyFn: GetKeyFn;
  let prevjwksUri: string;

  // Handle both string secrets (symmetric) and KeyLike objects (asymmetric)
  const secretKey = secret && (typeof secret === 'string'
    ? createSecretKey(Buffer.from(secret))
    : secret);

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
