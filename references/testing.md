# Testing

## Framework & layout

- **Jest + ts-jest** in the three library packages (`oauth2-bearer`, `access-token-jwt`, `express-oauth2-jwt-bearer` — each has a `jest.config.js`). The `examples` workspace has no test suite (its `test`/`lint`/`build` scripts are no-ops). Tests live in each library package's `test/` directory, written in TypeScript (`*.test.ts`). Config varies per package: `access-token-jwt` sets `testEnvironment: node` and `collectCoverageFrom: ['src/*']`; `oauth2-bearer` sets neither.
- **Coverage:** each library package enforces a **100% threshold** on branches, functions, lines, and statements (`coverageThreshold.global` in `jest.config.js`). `jest-junit` writes results under `test-results/`.
- **Run from root:** `npm test` aggregates `npm test --workspaces` (each package's `jest test --coverage`).

The suite is unit-only and requires no credentials: external HTTP (JWKS/discovery endpoints) is stubbed with `nock`.

## Running

```bash
npm test                                          # all packages
npm test --workspace=express-oauth2-jwt-bearer    # one package
npm test --workspace=access-token-jwt -- --coverage=false   # skip the coverage gate while iterating
npx jest test/index.test.ts --workspace=...        # a single file (or cd into the package and run npx jest)
```

## Conventions

- **Structure:** Jest `describe`/`it` blocks; assertions with Jest's built-in `expect`. `sinon` is available (in `access-token-jwt`) for stubs/spies where needed.
- **HTTP stubbing:** use `nock` to intercept JWKS and OAuth Authorization Server Metadata (discovery) requests; tests drive the Express middleware with `got` against an ephemeral `express` server.
- **Cross-package imports:** tests import sibling packages by their published name (`access-token-jwt`, `oauth2-bearer`), resolved via Jest `moduleNameMapper` and ts-jest `paths` to each sibling's `src/` — so you can run tests against source without building first. Test helpers are shared across packages (e.g. `access-token-jwt/test/helpers` `createJwt`).
- **Token fixtures:** JWTs are minted in-test (helper `createJwt`) with test keys — never real tokens.
