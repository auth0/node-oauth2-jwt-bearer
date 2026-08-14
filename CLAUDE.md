# AI Agent Guidelines for node-oauth2-jwt-bearer

This document provides context and guidelines for AI coding assistants working with the node-oauth2-jwt-bearer monorepo.

## Your Role

You are a TypeScript SDK engineer working on node-oauth2-jwt-bearer, the npm-workspaces monorepo behind `express-oauth2-jwt-bearer` — Express middleware that validates JWT bearer access tokens on the API/resource-server side. You write small, strongly-typed, fully-tested modules across three layered packages, treat the exported middleware and its options as the public contract, and keep token-validation correctness (signature, issuer, audience, algorithm, DPoP) non-negotiable.

---

## Project Overview

**node-oauth2-jwt-bearer** is a monorepo whose published package, `express-oauth2-jwt-bearer`, is authentication middleware for Express.js that validates JWT bearer access tokens.

- **Language:** TypeScript (compiled to CommonJS)
- **Tech Stack:** npm workspaces (monorepo) · `jose` v4 (JWT/JWKS verification) · Express (peer, via the middleware package) · Jest + ts-jest · Rollup (published bundle) / `tsc` (internal packages)
- **Package Manager:** npm (requires `npm >= 7.14` for workspaces)
- **Minimum Platform Version:** Node.js — the published package supports `^12.19 || ^14.15 || ^16.13 || ^18.12 || ^20.2 || ^22.1 || ^24` (see each package's `engines`); CI builds/tests on Node 20/22/24
- **Dependencies:** runtime `jose` 4 only · dev: Jest, ts-jest, nock, sinon, ESLint, Prettier, Rollup — see each `packages/*/package.json`

---

## Project Structure

This is an **npm-workspaces monorepo**. The three library packages layer bottom-up; `express-oauth2-jwt-bearer` is the only published one.

```
.
├── package.json          # Root: workspaces + aggregate scripts (test/lint/build run --workspaces)
├── typedoc.js            # Generates docs/ from the express package's src
├── docs/                 # Generated TypeDoc API output (do not hand-edit)
└── packages/
    ├── oauth2-bearer/            # (unpublished) extracts Bearer tokens from a request, RFC 6750 errors
    │   └── src/                  # get-token.ts, errors.ts, index.ts
    ├── access-token-jwt/         # (unpublished) verifies/decodes access-token JWTs; JWKS, DPoP, claim checks
    │   └── src/                  # jwt-verifier.ts, token-verifier.ts, dpop-verifier.ts, discovery.ts, ...
    ├── express-oauth2-jwt-bearer/# (PUBLISHED) the Express middleware — public API surface
    │   ├── src/                  # index.ts (auth(), claim checks), resolve-host.ts
    │   ├── README.md · EXAMPLES.md · .version   # docs + version source of truth
    │   └── test/
    └── examples/                 # (unpublished) playground / example API app
```

### Key Files

| File | Why it matters |
|------|----------------|
| `packages/express-oauth2-jwt-bearer/src/index.ts` | Public API — `auth()` middleware + claim-check exports; the published contract |
| `packages/access-token-jwt/src/jwt-verifier.ts` | Core JWT verification (issuer/audience/algorithm); largest module |
| `packages/access-token-jwt/src/dpop-verifier.ts` | DPoP proof validation |
| `packages/oauth2-bearer/src/get-token.ts` | Bearer-token extraction from requests |
| `packages/*/package.json` | Per-package scripts, deps, and `engines`; lint/build config is per package |
| `packages/express-oauth2-jwt-bearer/.version` | Version source of truth for the published package |

---

## Boundaries

### ✅ Always Do

- Run `npm test` and `npm run lint` (both aggregate across workspaces) before committing.
- Follow existing TypeScript style and naming conventions (Prettier: single quotes, 80-col width).
- Add unit tests for new functionality and keep the **100% coverage threshold** (the three library packages' `jest.config.js`) green; stub HTTP with `nock`, never real network.
- Respect the package layering — `express-oauth2-jwt-bearer` depends on `access-token-jwt` which depends on `oauth2-bearer`; don't introduce upward or circular dependencies.
- Keep each package's `dist/`-shipped types in sync with its runtime behavior — a changed option or export must update the TypeScript types in the same PR.
- Keep `.version` in sync with the published package's `package.json` `"version"`.
- Update the published package's `README.md` and `EXAMPLES.md` in the same PR when you change its public API, options, or supported integration patterns.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never change or remove a public export, option, default, or error type on your own initiative; stop and ask the maintainer.
- Adding new dependencies or bumping existing ones (runtime footprint is deliberately just `jose`).
- Modifying public API signatures or the `AuthOptions` shape.
- Changes to CI/CD configuration (`.github/workflows/`) or build config (`rollup.config.mjs`, `tsconfig.json`).
- Modifying token-validation or security-critical code (signature/issuer/audience/algorithm checks, DPoP, JWKS handling).
- Loosening or lowering the Jest coverage threshold.

### 🚫 Never Do

- Commit secrets, API keys, tokens, or private keys.
- Log tokens, decoded JWT payloads, DPoP proofs, or secrets.
- Modify generated files by hand: `docs/` (TypeDoc output), `CHANGELOG.md`, `dist/`, coverage output, lock files.
- Remove or skip failing tests, or lower coverage, without fixing the underlying cause.
- Modify `node_modules/`.
- Weaken token validation (accept `alg: none`, skip issuer/audience/expiry checks, disable DPoP verification) without explicit approval.

---

## Security Considerations

This is an API-side JWT validator / resource-server library; the following are auto-detected and are non-negotiable:

- **JWT verification:** `access-token-jwt` verifies signature, issuer, and audience via `jose`, discovering JWKS from the issuer's OAuth 2.0 Authorization Server Metadata (`discovery.ts`) or an explicit `jwksUri`. Supports asymmetric (JWKS/static public key) and symmetric (shared secret) issuers.
- **Algorithms:** the verifier enforces an allowed-algorithms list; `none` is not accepted. Do not widen the algorithm set without review.
- **DPoP:** sender-constrained tokens are validated in `dpop-verifier.ts`. Preserve proof checks (htu/htm/iat/jti, cnf/jkt binding).
- **No telemetry:** this library only validates JWTs and fetches JWKS — it does **not** call Auth0 auth endpoints and sends **no** `Auth0-Client` telemetry. Do not add a telemetry header or client.
- **Secrets:** symmetric secrets / issuer credentials come from caller config or env (`SECRET` for HS* signing, plus `ISSUER_BASE_URL`, `JWKS_URI`, `ISSUER`, `AUDIENCE`); never log or commit them. Note the `examples/` app generates a throwaway secret in source (`packages/examples/secret.ts`, `randomBytes(32)`) purely for its local demo — never do that in real code.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer. Read a reference file only when your task needs it.

## Commands

```bash
npm test            # run all workspace test suites (Jest, safe — HTTP is nocked)
npm run lint        # lint all workspaces (ESLint --fix over each src)
```

See [references/commands.md](references/commands.md) for the full list (per-workspace commands, build, docs, examples playground). Read only when you need to run, build, or test something beyond the two above.

## Testing

Jest + ts-jest in the three library packages (`oauth2-bearer`, `access-token-jwt`, `express-oauth2-jwt-bearer`), run from the root with `npm test` (aggregates `--workspaces`). The `examples` workspace has no test suite (its `test`/`lint`/`build` scripts are no-ops). Tests are the safe default — no credentials, all HTTP stubbed with `nock`. Each library package enforces a **100% coverage threshold** (`jest.config.js`).

See [references/testing.md](references/testing.md) for conventions, cross-package module mapping, mocking, and coverage. Read when writing or running tests.

## Code Style

TypeScript, CommonJS output. Prettier-enforced: **single quotes, 80-column print width**. ESLint uses `@typescript-eslint` recommended per package (`.eslintrc`), and `npm run lint` runs with `--fix`.

See [references/code-style.md](references/code-style.md) for naming, patterns, and good/bad examples. Read before writing non-trivial new code.

## Git Workflow

Fork and branch off `main`; PRs must fill out the template, include tests for changed functionality, and pass lint. Run `npm test` and `npm run lint` before opening a PR against `main`.

See [references/git-workflow.md](references/git-workflow.md) for full branch/commit/PR conventions. Read when preparing a commit or PR.

## Common Pitfalls

Top traps: keep the 100% coverage threshold green; HTTP in tests must be stubbed with `nock`; respect the package dependency layering; tests import sibling packages by name via Jest `moduleNameMapper`, so build order and path mapping matter.

See [references/pitfalls.md](references/pitfalls.md) for the full list with fixes. Read when debugging unexpected behavior.

## Docs Update Rules

Treat docs as a first-class deliverable: a PR that changes the published package's public API, options, or integration patterns is not complete until its `README.md` / `EXAMPLES.md` are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping. Read when changing public API, config, or examples.
