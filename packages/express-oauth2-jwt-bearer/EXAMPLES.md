# Examples

- [DPoP Authentication](#dpop-authentication)
  - [Accept both Bearer and DPoP tokens (default)](#accept-both-bearer-and-dpop-tokens-default)
  - [Require only DPoP tokens](#require-only-dpop-tokens)
  - [Require only Bearer tokens](#require-only-bearer-tokens)
  - [Customize DPoP validation behavior](#customize-dpop-validation-behavior)
  - [Hostname Resolution (`req.host` and `req.protocol`)](#hostname-resolution-reqhost-and-reqprotocol)
  - [DPoP jti Replay Prevention](#dpop-jti-replay-prevention)
- [mTLS Certificate-Bound Tokens](#mtls-certificate-bound-tokens)
  - [Resolve the client certificate with `getCertificate`](#resolve-the-client-certificate-with-getcertificate)
  - [Terminating TLS with a proxy](#terminating-tls-with-a-proxy)
  - [Accept both cert-bound and regular Bearer tokens (default once `getCertificate` is set)](#accept-both-cert-bound-and-regular-bearer-tokens-default-once-getcertificate-is-set)
  - [Require every token to be certificate-bound](#require-every-token-to-be-certificate-bound)
  - [Disable mTLS validation](#disable-mtls-validation)
  - [mTLS Behavior Matrix](#mtls-behavior-matrix)
  - [Using mTLS and DPoP together](#using-mtls-and-dpop-together)
- [Multiple Custom Domains (MCD)](#multiple-custom-domains-mcd)
  - [Static list of issuers](#static-list-of-issuers)
  - [Dynamic resolver](#dynamic-resolver)
- [Static Public Key Verification](#static-public-key-verification)
  - [PEM-encoded SPKI string](#pem-encoded-spki-string)
  - [Single JWK object](#single-jwk-object)
  - [Inline JWK Set](#inline-jwk-set)
- [Restrict access with scopes](#restrict-access-with-scopes)
- [Restrict access with claims](#restrict-access-with-claims)
  - [Matching a specific value](#matching-a-specific-value)
  - [Matching multiple values](#matching-multiple-values)
  - [Matching custom logic](#matching-custom-logic)
- [Anonymous Sessions](#anonymous-sessions)
  - [Block all anonymous callers globally](#block-all-anonymous-callers-globally)
  - [Block anonymous callers on specific routes](#block-anonymous-callers-on-specific-routes)
  - [Accept anonymous callers and branch in the handler](#accept-anonymous-callers-and-branch-in-the-handler)


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

#### Host Header Validation

The SDK validates the `Host` header to prevent security issues before constructing the request URL. Any `Host` header containing invalid characters (`/`, `?`, `#`, `://`) or failing to match the hostname grammar will be rejected with a `400 invalid_request` response.

This validation applies to all requests, not just DPoP requests. The hostname must conform to [RFC 7230](https://tools.ietf.org/html/rfc7230#section-2.7.1):

Valid hostnames:
- `example.com`
- `example.com:8443`
- `my_service:8080` (underscores are permitted per RFC 3986)
- `[::1]` (IPv6 literal)
- `[::1]:3000`

Invalid hostnames (will be rejected):
- `example.com/path` (path embedded in host)
- `example.com?query=value` (query in host)
- `https://example.com` (scheme in host)
- `example.com:99999` (port outside the valid 0–65535 range)

This is a security control that prevents host-injection attacks and does not require any configuration. Standards-compliant clients always send valid `Host` headers and are not affected.

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

## mTLS Certificate-Bound Tokens

[mTLS](https://www.rfc-editor.org/rfc/rfc8705) (Mutual TLS, RFC 8705) sender-constrains an access token to the client certificate that was used to obtain it. The authorization server embeds a `cnf.x5t#S256` claim (the base64url-encoded SHA-256 thumbprint of the client certificate) into the token. This middleware validates that claim: it recomputes the thumbprint of the certificate presented on the current TLS connection and rejects the request if it does not match.

Because APIs almost always run behind a TLS-terminating proxy (nginx, ALB, Cloudflare, etc.) that forwards the client certificate in a request header, the SDK cannot know where your certificate lives. You supply a `getCertificate` function that pulls it out of the request, and the SDK does the rest.

> mTLS is opt-in: unlike DPoP, it depends on a certificate resolver only you can supply, so it cannot safely default to on. Supplying `getCertificate` enables it automatically (`mtls.enabled` defaults to `true` once `getCertificate` is set); without `getCertificate`, `cnf.x5t#S256` claims are ignored entirely. Set `mtls: { enabled: false }` explicitly to keep mTLS off while still resolving certificates for your own use.

> mTLS and DPoP are mutually exclusive per token: a token carries at most one confirmation method. If a token is DPoP-bound (`cnf.jkt`), the DPoP path handles it and mTLS validation is skipped.

### Resolve the client certificate with `getCertificate`

`getCertificate(req)` returns the client certificate for the current request, or `undefined` when none is present. It may return either the PEM text (what most proxies forward, usually URL-encoded) or the raw DER bytes.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    getCertificate: (req) => {
      // nginx forwarding URL-encoded PEM in a header (see "Terminating TLS with a proxy" below):
      const pem = req.headers['client-certificate'];
      return typeof pem === 'string' ? decodeURIComponent(pem) : undefined;
    },
  })
);
```

If your Node process terminates TLS directly instead of sitting behind a proxy, return the peer certificate's DER bytes:

```js
getCertificate: (req) => req.socket.getPeerCertificate()?.raw || undefined;
```

### Terminating TLS with a proxy

Most deployments terminate TLS at a reverse proxy and forward the client certificate to the API in a request header. The header name and encoding are up to you; `getCertificate` just has to read it back out. For example, with nginx requesting the client certificate and forwarding it as URL-encoded PEM:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /path/to/server.crt;
    ssl_certificate_key /path/to/server.key;

    # Request the client certificate. Use `optional_no_ca` when the certificate
    # is validated downstream (e.g. by Auth0 at token issuance) rather than by
    # nginx; use `on` with `ssl_client_certificate` to have nginx verify a CA.
    ssl_verify_client optional_no_ca;

    location / {
        proxy_pass http://127.0.0.1:3000;
        # $ssl_client_escaped_cert is the URL-encoded PEM of the presented cert.
        proxy_set_header client-certificate $ssl_client_escaped_cert;
    }
}
```

The matching `getCertificate` reads that header and URL-decodes it, as shown in the example above.

> Only trust a forwarded client-certificate header on connections that reach your app **through** the proxy. If the app is also reachable directly, a client could set the header itself and forge a binding. Bind the app to a private interface (or otherwise restrict it to the proxy), and have the proxy overwrite the header on every request so an inbound value cannot pass through.

### Accept both cert-bound and regular Bearer tokens (default once `getCertificate` is set)

Once `getCertificate` is supplied, mTLS is enabled but not required by default. A certificate-bound token is validated against the presented certificate; a token with no `cnf.x5t#S256` claim passes through as a regular Bearer token.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    getCertificate: (req) => {
      const pem = req.headers['client-certificate'];
      return typeof pem === 'string' ? decodeURIComponent(pem) : undefined;
    },
    mtls: {
      enabled: true, // Validate cnf.x5t#S256 when present (default)
      required: false, // Non-bound tokens are still accepted (default)
    },
  })
);

app.get('/api/resource', (req, res) => {
  res.send('Access granted');
});
```

### Require every token to be certificate-bound

To reject any token that is not sender-constrained to a client certificate, set `required: true`. This matches an Auth0 Resource Server configured with **Token Sender-Constraining → mTLS → Always**.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    getCertificate: (req) => {
      const pem = req.headers['client-certificate'];
      return typeof pem === 'string' ? decodeURIComponent(pem) : undefined;
    },
    mtls: {
      enabled: true,
      required: true, // Reject tokens with no cnf.x5t#S256 binding
    },
  })
);

app.get('/api/secure-resource', (req, res) => {
  res.send('Certificate-bound token validated');
});
```

With `required: true` the SDK returns:

- `400 invalid_request` when a cert-bound token arrives but no certificate was presented on the connection.
- `401 invalid_token` when the presented certificate's thumbprint does not match the token's `cnf.x5t#S256`, or when the token carries no binding at all.

### Disable mTLS validation

To ignore `cnf.x5t#S256` claims entirely (for example while a certificate-bound token is still validated as a plain JWT):

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    mtls: {
      enabled: false, // cnf.x5t#S256 claims are not validated
    },
  })
);
```

### mTLS Behavior Matrix

| `getCertificate` | `enabled`         | `required` | Behavior                                                                                                                      |
| ----------------- | ----------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| not set            | not set            | `false`    | **Default**. mTLS is off; `cnf.x5t#S256` claims are ignored and tokens are accepted as plain Bearer JWTs.                     |
| set                | not set (→ `true`) | `false`    | **Default once `getCertificate` is set**. Cert-bound tokens are validated against the presented certificate; tokens with no `cnf.x5t#S256` pass through. |
| any                | `true`             | `true`     | Every token must be certificate-bound. A missing certificate → `400 invalid_request`; a thumbprint mismatch or unbound token → `401 invalid_token`. |
| any                | `false`            | `false`    | `cnf.x5t#S256` claims are not validated. Tokens are accepted as plain Bearer JWTs.                                            |
| any                | not `true`         | `true`     | Invalid configuration. `required` can only be `true` when `enabled` is also explicitly `true` (throws on startup).           |

### Using mTLS and DPoP together

An Auth0 Resource Server is configured with a single sender-constraining method, so in practice a token carries at most one confirmation claim (`cnf.jkt` for DPoP or `cnf.x5t#S256` for mTLS, never both). DPoP is enabled by default; mTLS is opt-in (see above). Each fires only for the tokens it applies to, so running both is safe. If you do run both, it helps to know how the SDK routes a request when both are enabled.

**DPoP is evaluated first and takes precedence.** For a given request the SDK runs at most one of the two verifiers. DPoP is checked first; mTLS validation runs only when the DPoP path does not apply. The DPoP path applies when the request uses the `DPoP` scheme, carries a `DPoP` proof header, has a `cnf.jkt` token, or DPoP is required. Otherwise the mTLS path applies to a `cnf.x5t#S256` token (or to every token when `mtls.required` is `true`).

Two consequences are worth calling out:

- **`mtls: { required: true }` is scoped to the mTLS path, not a global "every token must be certificate-bound" gate.** With DPoP also enabled, a valid DPoP-bound token is handled by the DPoP path and satisfies the request; the mTLS requirement is not applied to it. `mtls.required` rejects tokens that reach the mTLS path without a certificate binding, it does not override DPoP.
- **`dpop: { required: true }` makes the `mtls` options inert.** When DPoP is required, every request is routed to the DPoP path, so the mTLS verifier never runs regardless of the `mtls` configuration. Setting both `dpop.required` and `mtls.required` to `true` is contradictory (a token cannot be bound by both methods at once); the SDK does not reject that combination at startup, but DPoP wins and no token will ever be accepted by the mTLS path. Enable exactly one `required` method to match how your Resource Server is configured.

## Multiple Custom Domains (MCD)

Use `mcd` to accept JWT tokens from multiple custom domains belonging to the **same Authorization Server**. `mcd` and `issuerBaseURL` are mutually exclusive — use one or the other.

Common use cases:

- **Multi-brand applications (B2C)** — each brand uses a different custom domain but shares the same API (e.g. `brand-a.example.com` and `brand-b.example.com`).
- **Multiple frontend applications** — a single API serves multiple frontend apps, each with its own custom domain.
- **Domain migration** — gradually migrating traffic from a canonical Auth0 domain to a new custom domain without breaking existing tokens.

> **Note:** MCD is not a mechanism for accepting tokens from multiple Authorization Servers. All configured issuers must belong to the same Authorization Server.

### Security requirements

- **Use an allowlist.** The resolver must return only pre-approved issuer URLs. Never construct or look up discovery/JWKS URLs dynamically from request input.
- **Do not trust request-derived values directly.** `context.headers` and `context.url` come from the incoming request. Use them only to *select* from a hard-coded allowlist, never as URLs themselves.
- **Ensure HTTPS.** Custom `jwksUri` values in issuer configs must use HTTPS in production.
- **Single-tenant only.** All configured issuers must belong to the same Authorization Server.

### Static list of issuers

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    mcd: {
      issuers: [
        'https://brand-a.example.com',
        'https://brand-b.example.com',
      ]
    },
    audience: 'https://your-api.com'
  })
);
```

### Dynamic resolver

For apps where different custom domains map to different allowed issuers, use a resolver function. The resolver receives request context and must return an array of allowed issuer URLs or issuer config objects.

> **Security note:** `context.headers` and `context.url` are request-derived and must not be trusted directly. Use them only to select from a pre-approved allowlist. Ensure any header used for routing (e.g. `x-tenant-id`) is set by trusted upstream infrastructure such as your API gateway — never by the client.

```js
const { auth } = require('express-oauth2-jwt-bearer');

// ALLOWED_ISSUERS is a hard-coded allowlist — never build this from request input.
const ALLOWED_ISSUERS = {
  'tenant-a': ['https://brand-a.example.com'],
  'tenant-b': ['https://brand-b.example.com'],
};

app.use(
  auth({
    mcd: {
      issuers: async (context) => {
        // x-tenant-id must be set by trusted upstream middleware, not the client.
        const tenantId = context.headers['x-tenant-id'];
        const issuers = ALLOWED_ISSUERS[tenantId];
        if (!issuers) throw new Error('Unknown tenant');
        return issuers;
      }
    },
    audience: 'https://your-api.com'
  })
);
```

### Cache configuration

By default the SDK caches OIDC discovery metadata and JWKS responses (100 entries, 10-minute TTL each). Override with the `cache` option:

```js
auth({
  mcd: { issuers: [...] },
  audience: 'https://your-api.com',
  cache: {
    discovery: { maxEntries: 50, ttl: 300_000 }, // 5 minutes
    jwks:      { maxEntries: 50, ttl: 300_000 },
  }
})
```

## Static Public Key Verification

Use `publicKey` when you already have the issuer's public key and want to skip OIDC discovery and remote JWKS fetches entirely. This option is mutually exclusive with `issuerBaseURL`, `jwksUri`, and `secret`.

### PEM-encoded SPKI string

`tokenSigningAlg` is required when providing a PEM key, since the algorithm cannot be inferred from the key material alone.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuer: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
    tokenSigningAlg: 'RS256',
  })
);
```

### Single JWK object

The `alg` field in the JWK is used for algorithm selection. If omitted, provide `tokenSigningAlg`.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuer: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    publicKey: { kty: 'EC', crv: 'P-256', x: '...', y: '...', alg: 'ES256' },
  })
);
```

### Inline JWK Set

Key selection uses the token's `kid` header matched against each key's `kid` field. Useful when the issuer rotates keys.

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuer: 'https://YOUR_ISSUER_DOMAIN',
    audience: 'https://my-api.com',
    publicKey: {
      keys: [
        { kty: 'RSA', n: '...', e: 'AQAB', alg: 'RS256', kid: 'key-1' },
        { kty: 'RSA', n: '...', e: 'AQAB', alg: 'RS256', kid: 'key-2' },
      ],
    },
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

## Anonymous Sessions

> **Auth0-specific feature.** Requires the Anonymous Sessions add-on to be enabled on your Auth0 tenant.

Auth0 Anonymous Sessions issues standard JWT Bearer tokens to unauthenticated users. These tokens are validated by this SDK exactly like any other access token. The only distinguishing characteristic is that `sub` starts with `anon@` (e.g. `anon@abc123def456`).

By default, a valid anonymous token passes `auth()` just like an authenticated user's token. Use the patterns below to control access based on whether the caller is anonymous.

### Block all anonymous callers globally

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(
  auth({
    issuerBaseURL: 'https://YOUR_DOMAIN',
    audience: 'https://api.example.com',
    validators: {
      sub: (sub) => !sub.startsWith('anon@'),
    },
  })
);
```

### Block anonymous callers on specific routes

```js
const { auth, claimCheck } = require('express-oauth2-jwt-bearer');

app.use(auth({
  issuerBaseURL: 'https://YOUR_DOMAIN',
  audience: 'https://api.example.com',
}));

app.get('/checkout',
  claimCheck((payload) => !payload.sub?.startsWith('anon@')),
  (req, res) => { /* authenticated callers only */ }
);
```

### Accept anonymous callers and branch in the handler

```js
const { auth } = require('express-oauth2-jwt-bearer');

app.use(auth({
  issuerBaseURL: 'https://YOUR_DOMAIN',
  audience: 'https://api.example.com',
}));

app.get('/cart', (req, res) => {
  const isAnonymous = req.auth.payload.sub?.startsWith('anon@');
  // serve differently based on whether the caller is anonymous
});
```
