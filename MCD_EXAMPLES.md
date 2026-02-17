# Multiple Custom Domains (MCD) Guide

So you need to accept JWT tokens from multiple Auth0 tenants or custom domains? You're in the right place.

## What's this for?

If you're building an API that needs to support:
- Multiple Auth0 tenants (like different regions or customer segments)
- Custom domains alongside your main Auth0 domain
- Multi-tenant SaaS where each tenant has their own identity provider

Then MCD support will make your life easier. Instead of running separate API instances or juggling different middleware configs, you can handle everything in one place.

## How it works

The key security principle here: **we validate the issuer BEFORE fetching any keys**. This prevents attackers from putting malicious URLs in the `iss` claim and making your server fetch from internal networks (that's called SSRF, and it's bad).

Here's the flow:
1. Extract the `iss` claim from the incoming JWT (without trusting it yet)
2. Check if that issuer is in your allowed list
3. If yes, fetch the JWKS from that issuer and verify the signature
4. If no, reject the token immediately

No wasted network calls, no security holes.

## Three ways to configure it

### Option 1: Single domain (what you probably already have)

This is the standard setup. Nothing changes here:

```javascript
const { auth } = require('express-oauth2-jwt-bearer');

app.use(auth({
  issuerBaseURL: 'https://your-tenant.auth0.com',
  audience: 'https://your-api.com'
}));
```

Works exactly like before. No surprises.

### Option 2: Static list of domains

Got a fixed set of domains? Just list them:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: [
      'https://tenant1.auth0.com',
      'https://tenant2.auth0.com',
      'https://custom-domain.example.com'
    ]
  },
  audience: 'https://your-api.com'
}));
```

Tokens from any of these issuers will be accepted. Tokens from anywhere else get rejected.

You can also pass detailed config objects if you need more control:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: [
      {
        issuer: 'https://tenant1.auth0.com',
        alg: 'RS256'  // Optional: specify algorithm
      },
      {
        issuer: 'https://tenant2.auth0.com',
        jwksUri: 'https://tenant2.auth0.com/custom-jwks'  // Optional: custom JWKS location
      }
    ]
  },
  audience: 'https://your-api.com'
}));
```

Or if you have symmetric keys:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: [
      {
        issuer: 'https://tenant1.auth0.com',
        alg: 'HS256',
        secret: 'your-shared-secret'
      }
    ]
  },
  audience: 'https://your-api.com'
}));
```

### Option 3: Dynamic validation (for multi-tenant apps)

This is where it gets interesting. If you have a database of tenants and each tenant has their own allowed issuers, use a resolver function:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: async (context) => {
      // context gives you:
      // - url: the incoming request URL
      // - headers: the request headers

      // Example: check which tenant this request is for
      const tenantId = context.headers['x-tenant-id'];

      // Look up their config (from your database, cache, whatever)
      const tenant = await db.getTenant(tenantId);

      // Return their allowed issuers
      return tenant.allowedIssuers;
    }
  },
  audience: 'https://your-api.com'
}));
```

The resolver can return:
- An array of issuers: `['https://tenant1.auth0.com', 'https://tenant2.auth0.com']`
- Config objects: `[{ issuer: 'https://...', alg: 'RS256' }]`

Here's a more complete example showing different patterns:

```javascript
// Tenant database (actual database)
const tenants = {
  'acme-corp': {
    allowedIssuers: ['https://acme.auth0.com', 'https://auth.acme.com']
  },
  'globex-inc': {
    allowedIssuers: ['https://globex.auth0.com']
  }
};

app.use(auth({
  auth0MCD: {
    issuers: async (context) => {
      const tenantId = context.headers['x-tenant-id'];

      if (!tenantId) {
        return []; // No tenant = reject all
      }

      const tenant = tenants[tenantId];
      if (!tenant) {
        return []; // Unknown tenant = reject all
      }

      return tenant.allowedIssuers;
    }
  },
  audience: 'https://your-api.com'
}));
```

## Configuration Rules

### You must choose ONE configuration pattern

The SDK will throw a configuration error if you try to mix single-issuer and multi-issuer patterns:

**❌ This will fail:**
```javascript
app.use(auth({
  issuerBaseURL: 'https://tenant1.auth0.com',  // Single-issuer pattern
  auth0MCD: {                                    // Multi-issuer pattern
    issuers: ['https://tenant2.auth0.com']
  },
  audience: 'https://your-api.com'
}));
// Error: "You must not provide both 'auth0MCD' and 'issuerBaseURL'"
```

**❌ This will also fail:**
```javascript
app.use(auth({
  issuer: 'https://tenant1.auth0.com',         // Root-level issuer config
  jwksUri: 'https://tenant1.auth0.com/.well-known/jwks.json',
  auth0MCD: {                                    // MCD config
    issuers: ['https://tenant2.auth0.com']
  },
  audience: 'https://your-api.com'
}));
// Error: "You must not provide both 'auth0MCD' and 'issuer'"
```

### Why these errors?

These configuration patterns are **mutually exclusive**. Allowing both would create ambiguity:
- Which configuration takes precedence?
- Is `tenant1.auth0.com` allowed or not?
- Should the configs merge or override?

The error forces you to be explicit about your choice, preventing subtle bugs and confusion.

### Migration path

**If you're migrating from single-issuer to multi-issuer:**

```javascript
// Before (single issuer)
app.use(auth({
  issuerBaseURL: 'https://tenant1.auth0.com',
  audience: 'https://your-api.com'
}));

// After (multi-issuer)
app.use(auth({
  auth0MCD: {
    issuers: ['https://tenant1.auth0.com']  // Move issuer here
  },
  audience: 'https://your-api.com'
}));
```

Just remove the old config and add `auth0MCD`. Clean and simple.

## Caching

By default, three things get cached:

**OIDC Discovery** (per issuer, 10 minutes)
- The `.well-known/openid-configuration` responses
- Each issuer's discovery doc is cached separately

**JWKS Keys** (per issuer, 10 minutes with 30-second cooldown)
- The public keys used to verify signatures
- Each issuer's JWKS is cached independently

You can adjust the cache TTL:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: ['https://tenant1.auth0.com']
  },
  audience: 'https://your-api.com',
  cacheMaxAge: 300000  // Also affects JWKS and discovery
}));
```

## Troubleshooting

**"You must not provide both 'auth0MCD' and 'issuerBaseURL'" (or 'issuer' or 'jwksUri')**

You're mixing single-issuer and multi-issuer configuration patterns. Choose one:
- For single issuer: Use `issuerBaseURL` (or `issuer` + `jwksUri`)
- For multiple issuers: Use `auth0MCD` only

See the [Configuration Rules](#configuration-rules) section for migration guidance.

**"Issuer 'https://...' is not allowed"**

The token's `iss` claim doesn't match any of your configured issuers. Check:
- Is the issuer URL spelled correctly?
- Does it have the right protocol (https vs http)?
- Are you handling trailing slashes consistently?
- If using a resolver, is it returning the right issuers?

**"Token missing required 'iss' claim"**

The JWT doesn't have an `iss` claim. This is required for MCD to work. Make sure your tokens are properly formed.

**"Symmetric algorithms (HS256, HS384, HS512) are not supported..."**

You're receiving a symmetric token but haven't configured a secret. Either:
- Add the secret to your issuer config
- Or switch to asymmetric tokens (RS256 is the Auth0 default)

**"Discovery metadata issuer '...' does not match token issuer '...'"**

The issuer's discovery document claims to be a different issuer than what's in the token. This usually means:
- Misconfigured discovery endpoint
- MITM attack (unlikely but possible)
- Issuer URL doesn't match between token and discovery

**Dynamic resolver not being called**

Make sure you're NOT mixing patterns (see [Configuration Rules](#configuration-rules)):
- Can't use both `auth0MCD` and `issuerBaseURL` (or `issuer` or `jwksUri`)
- Resolver function should be async or return a Promise
- Check for errors in your resolver (they'll show up in console)

## What about...?

**DPoP tokens?**

Still work. MCD doesn't affect DPoP validation.

**Custom validators?**

Still work. Add them alongside MCD config:

```javascript
app.use(auth({
  auth0MCD: {
    issuers: ['https://tenant.auth0.com']
  },
  audience: 'https://your-api.com',
  validators: {
    org_id: (org, claims) => org === 'expected-org'
  }
}));
```

**Rate limiting the resolver?**

That's on you. The resolver function is called for each request (unless the result is cached via internal mechanisms). If you're doing database lookups, consider:
- Adding your own caching layer
- Using a fast cache like Redis
- Pre-loading tenant configs on startup

**What about backwards compatibility?**

Everything works exactly as before. The old single-issuer pattern (`issuerBaseURL`) is unchanged. Only add `auth0MCD` if you need multi-issuer support.

## Getting started

1. **Choose your configuration pattern:**
   - Fixed set of domains? → Static array
   - Dynamic multi-tenant? → Resolver function
   - Single domain? → Keep using `issuerBaseURL`

2. **Configure your issuers** with the actual Auth0 tenant URLs or custom domains

3. **Deploy** - all security validations are built-in

4. **Monitor logs** to confirm tokens are being accepted from the expected issuers

5. **Consider caching** if using a dynamic resolver with database lookups

That's it. You're ready to handle tokens from multiple domains securely.
