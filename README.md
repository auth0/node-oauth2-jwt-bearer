# oauth2-jwt-bearer

Monorepo for `oauth2-jwt-bearer`. Contains the following packages:

| package                                                           | published | description                                                                                                                                                      |
|-------------------------------------------------------------------|:---------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [oauth2-bearer](./packages/oauth2-bearer)                         |     ✘     | Gets Bearer tokens from a request and issues errors per [rfc6750](https://tools.ietf.org/html/rfc6750)                                                           |
| [access-token-jwt](./packages/access-token-jwt)                   |     ✘     | Verfies and decodes Access Token JWTs loosley following [draft-ietf-oauth-access-token-jwt-12](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-12) |
| [express-oauth2-jwt-bearer](./packages/express-oauth2-jwt-bearer) |     ✔     | Authentication middleware for Express.js that validates JWT Bearer Access Tokens                                                                                 |

## Developing

This package uses npm workspaces. You must have `npm >= @7.7` to develop this package

To run a command in the context of a workspace from the root use the `--workspace` or `--workspaces` arguments.

```shell
# build oauth2-bearer
npm run build --workspace=oauth2-bearer

# run all tests
npm test --workspaces # you can also use the `npm test` script
```

### Playground app

```shell
npm run dev --workspace=packages/examples
```

### Install new packages

You can't yet run `npm install` with the `workspace` flag, so to install something - don't run install from the workspace, instead from the root run:

```sh
# to install 'jest' to 'packages/oauth2-bearer'
npm run install:workspace -- packages/oauth2-bearer jest
```

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/.github/blob/master/CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

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

## Support + Feedback

Please use the [Issues queue](https://github.com/auth0/node-oauth2-jwt-bearer/issues) in this repo for questions and feedback.

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
