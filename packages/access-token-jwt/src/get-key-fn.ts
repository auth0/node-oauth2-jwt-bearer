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
  secret,
  cooldownDuration,
  timeoutDuration,
  cacheMaxAge,
}: JWKSOptions) => {
  let getKeyFn: GetKeyFn;
  let prevjwksUri: string;

  const secretKey = secret && createSecretKey(Buffer.from(secret));

  return (jwksUri: string) => {
    if (secretKey) return () => secretKey;
    if (!getKeyFn || prevjwksUri !== jwksUri) {
      prevjwksUri = jwksUri;
      getKeyFn = createRemoteJWKSet(new URL(jwksUri), {
        cooldownDuration,
        timeoutDuration,
        cacheMaxAge,
      });
    }
    return getKeyFn;
  };
};
