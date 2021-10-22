# express-oauth2-jwt-bearer

Authentication middleware for Express.js that validates JWT Bearer Access Tokens.

[![CircleCI](https://img.shields.io/circleci/build/github/auth0/node-oauth2-jwt-bearer.svg?branch=master&style=flat)](https://circleci.com/gh/auth0/node-oauth2-jwt-bearer)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![npm](https://img.shields.io/npm/v/express-oauth2-jwt-bearer.svg?style=flat)](https://www.npmjs.com/package/express-oauth2-jwt-bearer)
[![codecov](https://img.shields.io/badge/coverage-100%25-green)](./jest.config.js#L6-L13)

- [Install](#install)
- [Getting started](#getting-started)
- [API Documentation](#api-documentation)
- [Examples](#examples)
- [Security Headers](#security-headers)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [Support + Feedback](#support---feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0?](#what-is-auth0-)
- [License](#license)

## Install

This package supports Node `^12.19.0 || ^14.15.0`

```shell
npm install express-oauth2-jwt-bearer
```

## Getting started

The library requires [issuerBaseURL](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/authoptions.html#issuerbaseurl) and [audience](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/authoptions.html#audience), which can be configured with environmental variables:

```shell
ISSUER_BASE_URL=https://YOUR_ISSUER_DOMAIN
AUDIENCE=https://my-api.com
```

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(auth());
```

... or in the library initialization:

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(
    auth({
      issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
      audience: 'https://my-api.com'
    })
);
```

... or for JWTs signed with symmetric algorithms (eg `HS256`)

```js
const { auth } = require('express-oauth2-jwt-bearer');
app.use(
    auth({
      issuer: 'https://YOUR_ISSUER_DOMAIN',
      audience: 'https://my-api.com',
      secret: 'YOUR SECRET',
      tokenSigningAlg: 'HS256'
    })
);
```

With this basic configuration, your api will require a valid Access Token JWT bearer token for all routes.

## API Documentation

- [auth](https://auth0.github.io/node-oauth2-jwt-bearer#auth) - Middleware that will return a 401 if a valid Access token JWT bearer token is not provided in the request.
- [requiredScopes](https://auth0.github.io/node-oauth2-jwt-bearer#requiredscopes) - Check a token's scope claim to include a number of given scopes, raises a 403 `insufficient_scope` error if the value of the scope claim does not include all the given scopes.
- [claimEquals](https://auth0.github.io/node-oauth2-jwt-bearer#claimequals) - Check a token's claim to be equal a given JSONPrimitive (string, number, boolean or null) raises a 401 `invalid_token` error if the value of the claim does not match.
- [claimIncludes](https://auth0.github.io/node-oauth2-jwt-bearer#claimincludes) - Check a token's claim to include a number of given JSONPrimitives (string, number, boolean or null) raises a 401 `invalid_token` error if the value of the claim does not include all the given values.
- [claimCheck](https://auth0.github.io/node-oauth2-jwt-bearer#claimcheck) - Check the token's claims using a custom method that receives the JWT Payload and should return `true` if the token is valid. Raises a 401 `invalid_token` error if the function returns `false`.

## Examples

```js
const {
  auth,
  requiredScopes,
  claimEquals,
  claimIncludes,
  claimCheck
} = require('express-oauth2-jwt-bearer');

// Initialise the auth middleware with environment variables and restrict
// access to your api to users with a valid Access Token JWT
app.use(auth());

// Restrict access to the messages api to users with the `read:msg`
// AND `write:msg` scopes  
app.get('/api/messages',
    requiredScopes('read:msg', 'write:msg'),
    (req, res, next) => {
      // ...
    }
);

// Restrict access to the admin api to users with the `isAdmin: true` claim
app.get('/api/admin', claimEquals('isAdmin', true), (req, res, next) => {
  // ...
});

// Restrict access to the managers admin api to users with both the role `admin`
// AND the role `manager`
app.get('/api/admin/managers',
    claimIncludes('role', 'admin', 'manager'),
    (req, res, next) => {
      // ...
    }
);

// Restrict access to the admin edit api to users with the `isAdmin: true` claim
// and the `editor` role.
app.get('/api/admin/edit',
    claimCheck(({ isAdmin, roles }) => isAdmin && roles.includes('editor')),
    (req, res, next) => {
      // ...
   }
);
```

## Security Headers

Along with the other [security best practices](https://expressjs.com/en/advanced/best-practice-security.html) in the Express.js documentation, we recommend you use [helmet](https://www.npmjs.com/package/helmet) in addition to this middleware which can help protect your app from some well-known web vulnerabilities by setting default security HTTP headers.

## Error Handling

This SDK raises errors with `err.status` and `err.headers` according to [rfc6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3). The Express.js default error handler will set the error response with:

- `res.statusCode` set from `err.status`
- `res.statusMessage` set according to the status code.
- The body will be the HTML of the status code message when in production environment, otherwise will be `err.stack`.
- Any headers specified in an `err.headers` object.

The `error_description` in the `WWW-Authenticate` header will contain useful information about the error, which you may not want to disclose in Production.

See the Express.js [docs on error handling](https://expressjs.com/en/guide/error-handling.html) for more information on writing custom error handlers.

## Contributing

See monorepo's [contributing guidelines](../../README.md#contributing).

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
