import validate, { Validators, defaultValidators } from '../src/validate';

const header = {
  alg: 'RS256',
  typ: 'JWT',
};
const payload = {
  iss: 'https://issuer.example.com',
  aud: 'http://api.example.com',
  exp: ((Date.now() / 1000) | 0) + 60 * 60,
  iat: (Date.now() / 1000) | 0,
};
const validators: Validators = defaultValidators(
  'https://issuer.example.com',
  'http://api.example.com',
  10,
  10,
  false
);

describe('validate', () => {
  it('should validate a jwt with default validators', async () => {
    await expect(validate(payload, header, validators)).resolves.not.toThrow();
  });
  it('should throw for invalid alg header', async () => {
    await expect(
      validate(payload, { ...header, alg: 'none' }, validators)
    ).rejects.toThrow('unexpected "alg" value');
  });
  it('should disable alg header check', async () => {
    await expect(
      validate(payload, { ...header, alg: 'none' }, { ...validators })
    ).rejects.toThrow('unexpected "alg" value');
  });
});
