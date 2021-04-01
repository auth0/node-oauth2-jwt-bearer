# oauth2-jwt-bearer

Monorepo for oauth2-jwt-bearer 

## Development

This package uses npm workspaces. You must have `npm >= @7.7` to develop this package

To run a command in the context of a workspace from the root use the `--workspace` or `--workspaces` arguments.

```shell
# build oauth2-bearer
npm run build --workspace=oauth2-bearer

# run all tests
npm test --workspaces
```

You can't yet run `npm install` with the `workspace` flag, so to install something - don't run install from the workspace, instead from the root run:

```sh
# to install 'jest' to 'packages/oauth2-bearer'
npm install --package-lock-only --no-package-lock --save-dev --prefix=packages/oauth2-bearer jest
npm install
```
