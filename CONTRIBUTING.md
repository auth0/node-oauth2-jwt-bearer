# Contributing

Contributions can be made to this library through PRs to fix issues, improve documentation or add features. Please fork this repo, create a well-named branch, and submit a PR with a complete template filled out.

Code changes in PRs should be accompanied by tests covering the changed or added functionality. Tests can be run for this library with:

```bash
npm install
npm test
```

When you're ready to push your changes, please run the lint command first:

```bash
npm run lint
```

## Developing

This monorepo uses npm workspaces. You must have `npm >= @7.14` to develop this package

To run a command in the context of a workspace from the root use the `--workspace` or `--workspaces` arguments.

```shell
# install jose on access-token-jwt
npm run install jose --workspace=access-token-jwt

# build oauth2-bearer
npm run build --workspace=oauth2-bearer

# run all tests
npm test --workspaces # you can also use the `npm test` script
```

### Playground app

```shell
npm run dev --workspace=packages/examples
```