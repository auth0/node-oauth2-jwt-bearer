# Examples

- [DPoP Authentication](#dpop-authentication)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
  - [Customize DPoP validation behavior](#customize-dpop-validation-behavior)
  - [Hostname Resolution (`req.host` and `req.protocol`)](#hostname-resolution-reqhost-and-reqprotocol)
  - [DPoP jti Replay Prevention](#dpop-jti-replay-prevention)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Static list of issuers](#static-list-of-issuers)
  - [Dynamic resolver](#dynamic-resolver)
- [Restrict access with scopes](#restrict-access-with-scopes)
- [Restrict access with claims](#restrict-access-with-claims)
  - [Matching a specific value](#matching-a-specific-value)
  - [Matching multiple values](#matching-multiple-values)
  - [Matching custom logic](#matching-custom-logic)


## DPoP Authentication

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

### DPoP jti Replay Prevention

> [!WARNING]
> **Security Notice**: The SDK validates that the `jti` (JWT ID) claim exists in DPoP proofs and verifies the proof signature, but it does **not** cache or validate `jti` uniqueness. This means the same DPoP proof can be replayed multiple times within its validity window.
>
> **For production use, you MUST implement your own `jti` validation logic to prevent replay attacks.**

#### What the SDK validates
- DPoP proof signature and structure
- `ath` (access token hash) matches the access token
- `htm` (HTTP method) and `htu` (HTTP URI) match the request
- `iat` (issued at) is within the acceptable time range
- `jti` claim exists

#### What the SDK does not validate
- `jti` uniqueness across requests (replay prevention)

#### Implementation Example: In-Memory Cache (Development/Single Instance)

```js
 const express = require('express');
const { auth } = require('express-oauth2-jwt-bearer');

const jtiCache = new Map();

const validateDPoPJti = (req, res, next) => {
  const dpopProof = req.headers['dpop'];
  if (!dpopProof) return next();

  const [, payloadB64] = dpopProof.split('.');
  const payload = JSON.parse(
    Buffer.from(payloadB64, 'base64url').toString()
  );

  const { jti, iat } = payload;

  if (jtiCache.has(jti)) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'DPoP proof has already been used'
    });
  }

  // Default validity window: 300s + 30s
  jtiCache.set(jti, (iat + 330) * 1000);
  next();
};

const app = express();

app.use(auth({
  issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
  audience: 'https://my-api.com',
  dpop: { enabled: true }
}));

app.use(validateDPoPJti);

app.get('/api/protected', (req, res) => {
  res.json({ message: 'Access granted' });
});
```

#### Implementation Example: Redis (Production/Multi-Instance)

For production deployments with multiple server instances, use a shared cache like Redis:

```js
const express = require('express');
const { auth } = require('express-oauth2-jwt-bearer');
const Redis = require('ioredis');

const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
});

const validateDPoPJtiWithRedis = async (req, res, next) => {
  const dpopProof = req.headers['dpop'];

  if (!dpopProof) {
    return next();
  }

  try {
    const [, payloadB64] = dpopProof.split('.');
    const payload = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString()
    );
    const { jti, iat } = payload;

    // Check if jti exists in Redis
    const exists = await redis.exists(`dpop:jti:${jti}`);

    if (exists) {
      return res.status(401)
        .set('WWW-Authenticate', 'DPoP error="use_dpop_nonce", error_description="DPoP proof has already been used"')
        .json({
          error: 'use_dpop_nonce',
          error_description: 'DPoP proof has already been used'
        });
    }

    // Store jti with TTL matching the proof's validity window
    const now = Math.floor(Date.now() / 1000);
    const ttlSeconds = Math.max(1, (iat + 330) - now); // iat + iatOffset + iatLeeway
    await redis.setex(`dpop:jti:${jti}`, ttlSeconds, '1');

    next();
  } catch (err) {
    next(err);
  }
};

const app = express();

app.use(auth({
  issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
  audience: 'https://my-api.com',
  dpop: { enabled: true }
}));

app.use(validateDPoPJtiWithRedis);

app.get('/api/protected', (req, res) => {
  res.json({ message: 'Access granted' });
});
```

## Multiple Custom Domains (MCD)

Use `auth0MCD` to accept JWT tokens from multiple Auth0 tenants or custom domains. `auth0MCD` and `issuerBaseURL` are mutually exclusive — use one or the other.

### Static list of issuers

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    auth0MCD: {
      issuers: [
        'https://tenant1.auth0.com',
        'https://tenant2.auth0.com',
        'https://custom-domain.example.com'
      ]
    },
    audience: 'https://your-api.com'
  })
);
```

### Dynamic resolver

For multi-tenant apps where each tenant has their own allowed issuers:

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    auth0MCD: {
      issuers: async (context) => {
        const tenantId = context.headers['x-tenant-id'];
        const tenant = await db.getTenant(tenantId);
        return tenant.allowedIssuers; // e.g. ['https://tenant.auth0.com']
      }
    },
    audience: 'https://your-api.com'
  })
);
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