# Commands

Full command reference for node-oauth2-jwt-bearer. Root scripts aggregate across workspaces; per-package scripts run one package. All map to scripts in `package.json` / `packages/*/package.json` and jobs in `.github/workflows/test.yml`.

## Root (all workspaces)

```bash
npm install              # install all workspace deps (npm >= 7.14 required)
npm test                 # run every package's test suite (npm test --workspaces)
npm run lint             # lint every package (npm run lint --workspaces)
npm run build            # build every package (npm run build --workspaces)
npm run docs             # generate TypeDoc API docs into docs/ (typedoc --options typedoc.js)
```

## Per-package

Run a single workspace with `--workspace=<name>`:

```bash
npm test  --workspace=express-oauth2-jwt-bearer     # jest test --coverage
npm run lint  --workspace=access-token-jwt          # eslint --fix --ext .ts ./src
npm run build --workspace=oauth2-bearer             # tsc (prebuild: rimraf dist)
npm run dev   --workspace=packages/examples         # run the examples playground app
```

Build notes: `oauth2-bearer` and `access-token-jwt` compile with `tsc`; the published `express-oauth2-jwt-bearer` bundles with **Rollup** (`rollup -c`, `rollup.config.mjs`). Every package's `prebuild` runs `rimraf dist` first.

## What CI runs

`.github/workflows/test.yml`, gated on a build job (composite action `.github/actions/build`):

- **build** — `npm run build` on Node 20 / 22 / 24
- **unit** — `npm run test` on Node 20 / 22 / 24, then uploads coverage to Codecov
- **lint** — `npm run lint`

Other workflows: `codeql.yml`, `snyk.yml`, `rl-secure.yml` (security scans), `npm-release.yml` / `publish.yml` (release/publish — cut by the release process, not by an agent).
