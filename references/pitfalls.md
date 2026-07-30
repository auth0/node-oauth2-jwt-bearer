# Common Pitfalls

- **100% coverage is enforced.** Each of the three library packages' `jest.config.js` sets a `coverageThreshold.global` of 100% (branches/functions/lines/statements). A new branch or line without a covering test fails `npm test`. Add tests for every path, including error paths. (The `examples` workspace has no test suite — its scripts are no-ops.)

- **Network is expected to be stubbed.** Tests use `nock` to intercept JWKS and OAuth discovery requests. A code path that makes an unmocked outbound call will hang or fail — register a `nock` interceptor for the well-known metadata and JWKS endpoints.

- **Respect the package layering.** `express-oauth2-jwt-bearer` → `access-token-jwt` → `oauth2-bearer`. Don't add an upward dependency (a lower package importing a higher one) or a circular one. Shared logic belongs in the lowest package that needs it.

- **Cross-package imports resolve to `src/`, not `dist/`.** Tests import siblings by package name (`access-token-jwt`, `oauth2-bearer`) via Jest `moduleNameMapper` + ts-jest `paths`. This works without building, but means a build-time-only mistake (e.g. a bad barrel export) may pass tests yet break the Rollup bundle — run `npm run build` when touching exports.

- **`jwt-verifier.ts` and `token-verifier.ts` are large and security-critical.** Most validation logic (issuer resolution, algorithm allowlist, audience, DPoP wiring) lives here. Changes have wide blast radius and touch security — keep edits surgical, add targeted tests, and treat validation-weakening changes as Ask First.

- **Only `express-oauth2-jwt-bearer` is published.** `oauth2-bearer` and `access-token-jwt` are `private: true` at `0.0.1` and shipped bundled into the published package. Don't document them as separately installable, and remember the published version source is `packages/express-oauth2-jwt-bearer/.version`.

- **Two build tools.** Internal packages use `tsc`; the published package uses Rollup (`rollup.config.mjs`). When changing build behavior, edit the right one.

- **No telemetry by design.** This is an API-side validator — it must not send an `Auth0-Client` header or call Auth0 auth endpoints. Don't "add telemetry" here.
