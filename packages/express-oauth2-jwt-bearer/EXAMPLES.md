# Examples

- [DPoP Authentication (Early Access)](#dpop-authentication-early-access)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
  - [Customize DPoP validation behavior](#customize-dpop-validation-behavior)
  - [Hostname Resolution (`req.host` and `req.protocol`)](#hostname-resolution-reqhost-and-reqprotocol)
  
- [Restrict access with scopes](#restrict-access-with-scopes)
- [Restrict access with claims](#restrict-access-with-claims)
  - [Matching a specific value](#matching-a-specific-value)
  - [Matching multiple values](#matching-multiple-values)
  - [Matching custom logic](#matching-custom-logic)


## DPoP Authentication (Early Access) 
> [!NOTE]  
> DPoP (Demonstration of Proof-of-Possession) support is currently in [**Early Access**](https://auth0.com/docs/troubleshoot/product-lifecycle/product-release-stages#early-access). Contact Auth0 support to enable it for your tenant.
>
> If DPoP is disabled (`dpop: { enabled: false }`), only standard Bearer tokens will be accepted.

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Posession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the client application is in possession of a certain private key.
By default, DPoP is enabled but not required. This means that the middleware will accept both Bearer and DPoP tokens.
### Accept both Bearer and DPoP tokens (default)
```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    dpop: {
      enabled: true,   // Enables DPoP support
      required: false  // Accepts both Bearer and DPoP tokens (default)
    }
  })
);

app.get('/api/resource', (req, res) => {
  res.send('Access granted');
});
```
Requests using DPoP must include both `Authorization` and `DPoP` headers:
```http
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6...
DPoP: eyJhbGciOiJkcG9wIiwidHlwIjoi...
```

### Require only DPoP tokens
To enforce stronger protection and reject non-DPoP tokens:
```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    dpop: {
      enabled: true,
      required: true  // Rejects Bearer tokens
    }
  })
);

app.get('/api/secure-resource', (req, res) => {
  res.send('DPoP token validated');
});
```

### Require only Bearer tokens
If you want to reject all DPoP tokens and only accept standard Bearer access tokens, you can disable DPoP support explicitly:

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    dpop: {
      enabled: false  // DPoP proofs will be ignored
    }
  })
);

app.get('/api/bearer-only', (req, res) => {
  res.send('This route accepts only Bearer tokens');
});
```

### Customize DPoP validation behavior
```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    dpop: {
      enabled: true,
      required: true,
      iatOffset: 300,   // Reject proofs older than 5 minutes
      iatLeeway: 30,    // Allow 30s clock skew
    }
  })
);
```
#### DPoP Behavior Matrix

| `enabled` | `required` | Behavior                                                                                             |
| --------- | ---------- | -----------------------------------------------------------------------------------------------------|
| `true`    | `false`    | **Default behavior**. Both Bearer and DPoP tokens are accepted. Proofs are validated if present.     |
| `false`   | `false`    | Only Bearer tokens are accepted. Rejects any non-Bearer scheme tokens (including DPoP). Accepts DPoP-bound tokens over Bearer (ignoring `cnf`) and ignores any DPoP proof headers if present. |
| `false`   | `true`     | Invalid configuration. DPoP is ignored, so `required: true` has no effect. DPoP is ignored entirely. |
| `true`    | `true`     | Only DPoP tokens are accepted. Bearer tokens are rejected.                                           |


#### Proof Timing Options

When DPoP is enabled, you can control the accepted timing of DPoP proofs using the following options:

  - `iatOffset`: The maximum age (in seconds) of a DPoP proof. Proofs with `iat` older than this offset (relative to now) will be rejected.
    Default: `300 seconds`(5 minutes)

  - `iatLeeway`: Clock skew tolerance (in seconds) when comparing a proof's `iat` with the current server time.
    Default: `30 seconds`

### Hostname Resolution (`req.host` and `req.protocol`)
This SDK uses `req.protocol` and `req.host` to construct the `htu` (HTTP URI) claim for validating DPoP proofs.
  - The values of `req.host` and `req.protocol` are determined by Express.
  - If your application is behind a reverse proxy (e.g., Nginx, Cloudflare), you must enable proxy trust:

    ```js
    app.enable('trust proxy');
    ```

## Restrict access with scopes

To restrict access based on the scopes a user has, use the `requiredScopes` middleware, raising a 403 `insufficient_scope` error if the value of the scope claim does not include all the given scopes.

```js
const {
  auth,
  requiredScopes
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
```

## Restrict access with claims

### Matching a specific value

To restrict access based on the value of a claim use the `claimEquals` middleware. This checks that the claim exists and matches the expected value, raising a 401 `invalid_token` error if the value of the claim does not match.

```js
const {
  auth,
  claimEquals
} = require('express-oauth2-jwt-bearer');

// Initialise the auth middleware with environment variables and restrict
// access to your api to users with a valid Access Token JWT
app.use(auth());

// Restrict access to the admin api to users with the `isAdmin: true` claim
app.get('/api/admin', claimEquals('isAdmin', true), (req, res, next) => {
  // ...
});
```

### Matching multiple values

To restrict access based on a claim including multiple values use the `claimIncludes` middleware. This checks that the claim exists and the expected values are included, rasising a 401 `invalid_token` error if the value of the claim does not include all the given values


```js
const {
  auth,
  claimIncludes
} = require('express-oauth2-jwt-bearer');

// Initialise the auth middleware with environment variables and restrict
// access to your api to users with a valid Access Token JWT
app.use(auth());

// Restrict access to the managers admin api to users with both the role `admin`
// AND the role `manager`
app.get('/api/admin/managers',
    claimIncludes('role', 'admin', 'manager'),
    (req, res, next) => {
      // ...
    }
);
```

### Matching custom logic

To restrict access based on custom logic you can provide a function use `claimCheck`. This must be a function that  receives the JWT Payload and should return `true` if the token is valid, raising a 401 `invalid_token` error if the function returns `false`.

```js
const {
  auth,
  claimCheck
} = require('express-oauth2-jwt-bearer');

// Restrict access to the admin edit api to users with the `isAdmin: true` claim
// and the `editor` role.
app.get('/api/admin/edit',
    claimCheck(({ isAdmin, roles }) => isAdmin && roles.includes('editor')),
    (req, res, next) => {
      // ...
   }
);
```