# Code Style

## Enforced tooling

- **Prettier** (`packages/*/.prettierrc`): `singleQuote: true`, `printWidth: 80`.
- **ESLint** (`packages/*/.eslintrc`, `root: true` per package): `@typescript-eslint/parser` + `eslint:recommended` + `plugin:@typescript-eslint/eslint-recommended` + `plugin:@typescript-eslint/recommended`. Only `express-oauth2-jwt-bearer/.eslintrc` adds a `rules` override — `@typescript-eslint/no-namespace: off` (that package augments the Express `Request` namespace); the other two packages have no `rules` block, so a `namespace` there would fail CI lint. `*.js` is ignored. `npm run lint` runs ESLint with `--fix`.
- **TypeScript:** each package has its own `tsconfig.json` extending `@tsconfig/node12`; strict typing is expected.

There is no separate CI `format` step — Prettier conventions are folded into what you write; ESLint is the CI-enforced gate (`lint` job).

## Naming & module conventions

- TypeScript compiled to CommonJS (`main: dist/index.js`, `types: dist/index.d.ts`).
- File names are kebab-case (`get-token.ts`, `jwt-verifier.ts`, `dpop-verifier.ts`).
- `camelCase` for functions/variables, `PascalCase` for types/interfaces/classes and error types (`InvalidTokenError`, `AuthOptions`).
- Public exports flow through each package's `src/index.ts`; the middleware re-exports selected symbols from `access-token-jwt` (aliasing internals with a leading `_`).

## Patterns used here

- **Layered packages:** `oauth2-bearer` (transport/errors) → `access-token-jwt` (verification) → `express-oauth2-jwt-bearer` (Express glue). Keep responsibilities in the right layer; no upward/circular deps.
- **Typed OAuth errors:** throw the RFC 6750 error hierarchy from `oauth2-bearer` (`InvalidRequestError`, `InvalidTokenError`, `InsufficientScopeError`, `UnauthorizedError`) so the middleware maps them to the correct 400/401/403 + `WWW-Authenticate`, rather than bare `Error`.
- **Options-object API:** the middleware takes an `AuthOptions` object; claim checks (`claimEquals`, `claimIncludes`, `requiredScopes`, `scopeIncludesAny`) are composable factories.

## Examples

**✅ Good** — typed OAuth error, single quotes, option-driven:

```typescript
import { InvalidTokenError } from 'oauth2-bearer';

export const requireAudience = (audience: string) => (payload: JWTPayload) => {
  if (payload.aud !== audience) {
    throw new InvalidTokenError('Unexpected token audience');
  }
};
```

**❌ Bad** — bare `Error`, double quotes, untyped:

```typescript
export function requireAudience(audience) {           // missing types
  return (payload) => {
    if (payload.aud !== audience) {
      throw new Error("bad aud");                       // use the RFC 6750 error types; double quotes fail Prettier
    }
  };
}
```
