import { JWTPayload, JWSHeaderParameters } from 'jose/jwt/verify';

type ClaimValue = number | string | string[] | undefined;

export type Validator =
  | ((
      value: ClaimValue,
      claims: JWTPayload,
      header: JWSHeaderParameters
    ) => Promise<boolean> | boolean)
  | string
  | false;

export interface Validators {
  alg: Validator;
  typ: Validator;
  iss: Validator;
  aud: Validator;
  exp: Validator;
  iat: Validator;
  sub: Validator;
  client_id: Validator;
  jti: Validator;
  [key: string]: Validator;
}

const validateProperty = async (
  property: string,
  value: undefined | number | string | string[],
  validator: Validator,
  payload: JWTPayload,
  header: JWSHeaderParameters
): Promise<void> => {
  if (
    validator === false ||
    (typeof validator === 'string' && value === validator) ||
    (typeof validator === 'function' &&
      (await validator(value, payload, header)))
  ) {
    return;
  }
  throw new Error(`unexpected "${property}" value`);
};

export default (
  payload: JWTPayload,
  header: JWSHeaderParameters,
  validators: Validators
): Promise<void[]> =>
  Promise.all(
    Object.entries(validators).reduce(
      (acc: Promise<void>[], [key, val]: [string, Validator]) => {
        if (key === 'alg' || key === 'typ') {
          acc.push(validateProperty(key, header[key], val, payload, header));
        } else {
          acc.push(
            validateProperty(
              key,
              payload[key] as ClaimValue,
              val,
              payload,
              header
            )
          );
        }
        return acc;
      },
      []
    )
  );

export const defaultValidators = (
  issuer: string,
  audience: string | string[],
  clockTolerance: number,
  maxTokenAge: number | undefined,
  strict: boolean
): Validators => ({
  alg: (alg) => alg !== 'none',
  typ: (typ) =>
    !strict ||
    (typeof typ === 'string' &&
      typ.toLowerCase().replace(/^application\//, '') === 'at+jwt'),
  iss: (iss) => iss === issuer,
  aud: (aud) => {
    audience = typeof audience === 'string' ? [audience] : audience;
    if (typeof aud === 'string') {
      return audience.includes(aud);
    }
    if (Array.isArray(aud)) {
      return audience.some(Set.prototype.has.bind(new Set(aud)));
    }
    return false;
  },
  exp: (exp) => {
    const now = Math.floor(Date.now() / 1000);
    return typeof exp === 'number' && exp >= now - clockTolerance;
  },
  iat: (iat) => {
    if (!maxTokenAge) {
      return (iat === undefined && !strict) || typeof iat === 'number';
    }
    const now = Math.floor(Date.now() / 1000);
    return (
      typeof iat === 'number' &&
      iat < now + clockTolerance &&
      iat > now - clockTolerance - maxTokenAge
    );
  },
  sub: (sub) => (sub === undefined && !strict) || typeof sub === 'string',
  client_id: (clientId) =>
    (clientId === undefined && !strict) || typeof clientId === 'string',
  jti: (jti) => (jti === undefined && !strict) || typeof jti === 'string',
});
