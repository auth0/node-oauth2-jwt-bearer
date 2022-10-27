# Examples

- [Restrict access with scopes](#restrict-access-with-scopes)
- [Restrict access with claims](#restrict-access-with-claims)
  - [Matching a specific value](#matching-a-specific-value)
  - [Matching multiple values](#matching-multiple-values)
  - [Matching custom logic](#matching-custom-logic)


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