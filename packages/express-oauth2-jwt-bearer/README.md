![Authentication middleware for Express.js that validates JWT Bearer Access Tokens](https://cdn.auth0.com/website/sdks/banners/express-oauth2-jwt-bearer-banner.png)

[![npm](https://img.shields.io/npm/v/express-oauth2-jwt-bearer.svg?style=flat)](https://www.npmjs.com/package/express-oauth2-jwt-bearer)
[![codecov](https://img.shields.io/badge/coverage-100%25-green)](./jest.config.js#L6-L13)
![Downloads](https://img.shields.io/npm/dw/express-oauth2-jwt-bearer)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![CircleCI](https://img.shields.io/circleci/build/github/auth0/node-oauth2-jwt-bearer.svg?branch=master&style=flat)](https://circleci.com/gh/auth0/node-oauth2-jwt-bearer)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](#api-reference) - 💬 [Feedback](#feedback)

## Documentation

- [Docs Site](https://auth0.com/docs) - explore our Docs site and learn more about Auth0.

## Getting started

### Requirements

This package supports the following tooling versions:

- Node.js: `^12.19.0 || ^14.15.0 || ^16.13.0 || ^18.12.0 || ^20.2.0`

### Installation

Using [npm](https://npmjs.org) in your project directory run the following command:

```shell
npm install express-oauth2-jwt-bearer
```

## Getting started

### Configure the SDK

The library requires [issuerBaseURL](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/AuthOptions.html#issuerBaseURL) and [audience](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/AuthOptions.html#audience).

#### Environment Variables

```shell
ISSUER_BASE_URL=https://YOUR_ISSUER_DOMAIN
AUDIENCE=https://my-api.com
```

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(auth());
```

#### Library Initialization

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
  })
);
```

#### JWTs signed with symmetric algorithms (eg `HS256`)

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(
  auth({
    issuer: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    secret: 'YOUR SECRET',
    tokenSigningAlg: 'HS256',
  })
);
```

With this configuration, your api will require a valid Access Token JWT bearer token for all routes.

Successful requests will have the following properties added to them:

```js
app.get('/api/messages', (req, res, next) => {
  const auth = req.auth;
  auth.header; // The decoded JWT header.
  auth.payload; // The decoded JWT payload.
  auth.token; // The raw JWT token.
});
```

### Security Headers

Along with the other [security best practices](https://expressjs.com/en/advanced/best-practice-security.html) in the Express.js documentation, we recommend you use [helmet](https://www.npmjs.com/package/helmet) in addition to this middleware which can help protect your app from some well-known web vulnerabilities by setting default security HTTP headers.

### Error Handling

This SDK raises errors with `err.status` and `err.headers` according to [rfc6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3). The Express.js default error handler will set the error response with:

- `res.statusCode` set from `err.status`
- `res.statusMessage` set according to the status code.
- The body will be the HTML of the status code message when in production environment, otherwise will be `err.stack`.
- Any headers specified in an `err.headers` object.

The `error_description` in the `WWW-Authenticate` header will contain useful information about the error, which you may not want to disclose in Production.

See the Express.js [docs on error handling](https://expressjs.com/en/guide/error-handling.html) for more information on writing custom error handlers.

## API Reference

- [auth](https://auth0.github.io/node-oauth2-jwt-bearer/functions/auth.html) - Middleware that will return a 401 if a valid Access token JWT bearer token is not provided in the request.
- [AuthResult](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/AuthResult.html) - The properties added to `req.auth` upon successful authorization.
- [requiredScopes](https://auth0.github.io/node-oauth2-jwt-bearer/functions/requiredScopes.html) - Check a token's scope claim to include a number of given scopes, raises a 403 `insufficient_scope` error if the value of the scope claim does not include all the given scopes.
- [claimEquals](https://auth0.github.io/node-oauth2-jwt-bearer/functions/claimEquals.html) - Check a token's claim to be equal a given JSONPrimitive (string, number, boolean or null) raises a 401 `invalid_token` error if the value of the claim does not match.
- [claimIncludes](https://auth0.github.io/node-oauth2-jwt-bearer/functions/claimIncludes.html) - Check a token's claim to include a number of given JSONPrimitives (string, number, boolean or null) raises a 401 `invalid_token` error if the value of the claim does not include all the given values.
- [claimCheck](https://auth0.github.io/node-oauth2-jwt-bearer/functions/claimCheck.html) - Check the token's claims using a custom method that receives the JWT Payload and should return `true` if the token is valid. Raises a 401 `invalid_token` error if the function returns `false`.

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/node-oauth2-jwt-bearer/blob/main/packages/express-oauth2-jwt-bearer/LICENSE"> LICENSE</a> file for more info.
</p>
