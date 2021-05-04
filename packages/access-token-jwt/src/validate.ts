import { JWTPayload, JWSHeaderParameters } from 'jose/jwt/verify';

export type Validator =
  | ((
      value: number | string | string[] | undefined,
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
  sub: Validator;
  client_id: Validator;
  exp: Validator;
  iat: Validator;
  jti: Validator;
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
  throw new Error(`Unexpected "${property}" value`);
};

export default async (
  payload: JWTPayload,
  header: JWSHeaderParameters,
  validators: Validators
): Promise<void> => {
  await validateProperty('alg', header.alg, validators.alg, payload, header);
  await validateProperty('typ', header.typ, validators.typ, payload, header);
  await validateProperty('iss', payload.iss, validators.iss, payload, header);
  await validateProperty('aud', payload.aud, validators.aud, payload, header);
  await validateProperty('exp', payload.exp, validators.exp, payload, header);
};

export const defaultValidators = (
  issuer: string,
  audience: string | string[],
  clockTolerance: number,
  maxTokenAge: number | undefined,
  strict: boolean
): Validators => ({
  alg: (alg) => {
    return alg !== 'none';
  },
  typ: (typ) => {
    return (
      !strict ||
      (typeof typ === 'string' &&
        typ.toLowerCase().replace(/^application\//, '') === 'at+jwt')
    );
  },
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
  sub: false,
  client_id: false,
  exp: (exp) => {
    const now = Math.floor(Date.now() / 1000);
    return typeof exp === 'number' && exp >= now - clockTolerance;
  },
  iat: (iat) => {
    if (!maxTokenAge) {
      return iat === undefined || typeof iat === 'number';
    }
    const now = Math.floor(Date.now() / 1000);
    return (
      typeof iat === 'number' &&
      iat < now + clockTolerance &&
      iat > now - clockTolerance - maxTokenAge
    );
  },
  jti: false,
});
