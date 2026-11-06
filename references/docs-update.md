# Docs Update Rules

Treat documentation as a first-class deliverable. A PR that adds or changes public API, options, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

## Tracked docs

| Doc | Covers | Status |
|-----|--------|--------|
| `packages/express-oauth2-jwt-bearer/README.md` | Install, usage, `auth()` options, claim checks — the published package's primary docs | present |
| `packages/express-oauth2-jwt-bearer/EXAMPLES.md` | Runnable code samples and integration patterns (scopes, claims, DPoP, custom issuers) | present |
| `packages/examples/` | Playground / example API app exercising the middleware | present |
| Root `README.md` | Monorepo overview + package table (published vs. internal) | present |

> Not tracked here: `CHANGELOG.md` (cut by the release process, not agent-edited) and `docs/` plus `packages/express-oauth2-jwt-bearer/mintlify/` (generated TypeDoc output; the release regenerates both through `.shiprc`'s `postbump`, with source links pointing at the release tag from `.version`, so don't commit a regenerate between releases). The internal packages' `README.md` files (`oauth2-bearer`, `access-token-jwt`) describe unpublished internals and are lower priority than the published package's docs.

## When you change code, update these docs

This is a library/SDK; the public surface is the exports of `packages/express-oauth2-jwt-bearer/src/index.ts` and the `AuthOptions` shape (much of it re-exported from `access-token-jwt`).

| When this changes | Update these docs |
|-------------------|-------------------|
| `AuthOptions` / a middleware option added, removed, renamed, or default changed | express package `README.md` (options), `EXAMPLES.md` (affected samples) |
| A public export added/removed/renamed (`auth`, `claimCheck`, `claimEquals`, `claimIncludes`, `requiredScopes`, `scopeIncludesAny`, error types) | express package `README.md` (usage), `EXAMPLES.md` |
| Token-validation behavior (issuer/audience/algorithm, DPoP, claim checks) | express package `README.md`, `EXAMPLES.md` (auth examples) |
| Install requirements / supported Node versions (`engines`) | express package `README.md` (install/requirements) |
| A new integration pattern supported | `EXAMPLES.md` + the `packages/examples/` app when it warrants a runnable demo |
| The set/status of monorepo packages | root `README.md` package table |

> When you touch code that maps to a doc above, update that doc **in the same PR** — do not defer.

## API reference categories

Every public export carries a `@category` tag in its JSDoc (after any `@param`/`@returns`/`@example`). The Mintlify reference groups symbols by it, in the order of `categoryOrder` in `typedoc.js`: Getting Started, Configuration, Claim & Scope Checks, DPoP & mTLS, Multiple Issuers, Errors. An untagged export lands in "Other", and a new category missing from `categoryOrder` falls after Errors, so add it to `typedoc.js` too.
