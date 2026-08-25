[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/node-oauth2-jwt-bearer)

# oauth2-jwt-bearer

Monorepo for `oauth2-jwt-bearer`. Contains the following packages:

| package                                                           | published | description                                                                                                                                                      |
|-------------------------------------------------------------------|:---------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [oauth2-bearer](./packages/oauth2-bearer)                         |     ✘     | Gets Bearer tokens from a request and issues errors per [rfc6750](https://tools.ietf.org/html/rfc6750)                                                           |
| [access-token-jwt](./packages/access-token-jwt)                   |     ✘     | Verfies and decodes Access Token JWTs loosley following [draft-ietf-oauth-access-token-jwt-12](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-12) |
| [express-oauth2-jwt-bearer](./packages/express-oauth2-jwt-bearer) |     ✔     | Authentication middleware for Express.js that validates JWT Bearer Access Tokens                                                                                 |

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/node-oauth2-jwt-bearer/blob/main/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/node-oauth2-jwt-bearer/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/node-oauth2-jwt-bearer/blob/main/LICENSE"> LICENSE</a> file for more info.
</p>