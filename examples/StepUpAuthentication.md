# Step-Up Authentication (MFA)

Step-up authentication requires that a caller's access token was issued after MFA was completed before allowing a sensitive action (transferring funds, changing security settings, deleting data). The user's existing access token either carries the right claims already, or the client must redirect the user to Auth0 to re-authenticate with a stronger factor and obtain a new token.

With `express-oauth2-jwt-bearer` you enforce this **on the resource server** by checking the `amr` (Authentication Methods References) and/or `acr` (Authentication Context Class Reference) claims that Auth0 stamps into the access token via a custom Action.

> [!NOTE]
> This SDK validates access tokens that arrive at your API — it does not trigger or drive MFA. MFA happens at the Authorization Server (Auth0) during token issuance. Auth0 requires a custom Action to add `amr`/`acr` claims to access tokens; see [the Auth0 step-up authentication docs](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication) for tenant setup.

## How It Works

```
Client → [Auth0: login + MFA prompt] → Access token with amr: ["mfa"] → Your API
                                                                           ↑
                                               express-oauth2-jwt-bearer checks amr/acr here
```

1. Auth0 issues an access token with `amr: ["mfa"]` (and/or `acr` set to the requested policy URI) when the user completed MFA.
2. Your API validates the token with `express-oauth2-jwt-bearer` as usual.
3. A custom middleware reads `req.auth.payload.amr` (or `req.auth.payload.acr`) after the token is verified and returns `403` if MFA was not completed.

## Checking the amr Claim

Auth0 sets `amr` to an array that includes `"mfa"` when the user completed a second factor. Check it in custom middleware **after** `auth()` has validated the token:

```js
const { auth, requiredScopes } = require('express-oauth2-jwt-bearer');

const checkJwt = auth({
  issuerBaseURL: process.env.ISSUER_BASE_URL,
  audience: process.env.AUDIENCE,
});

const requireMfa = (req, res, next) => {
  const { amr } = req.auth?.payload ?? {};
  if (!Array.isArray(amr) || !amr.includes('mfa')) {
    return res.status(403).json({ code: 'mfa_required' });
  }
  next();
};

// GET /api/balance — scope check only, no MFA required
app.get('/api/balance',
  checkJwt,
  requiredScopes('read:balance'),
  (req, res) => res.json({ balance: 1000 })
);

// POST /api/transfers — scope check AND MFA required
app.post('/api/transfers',
  checkJwt,
  requiredScopes('write:transfers'),
  requireMfa,
  (req, res) => res.json({ status: 'transfer complete' })
);
```

> [!IMPORTANT]
> `requireMfa` must run **after** `checkJwt`. The `amr` claim is only available on `req.auth.payload` once `checkJwt` has validated and decoded the token. Placing `requireMfa` before `checkJwt` means `req.auth` is `undefined` and every request is rejected with `403` regardless of whether the caller completed MFA.

## Why Custom Middleware (Not claimIncludes)

`claimIncludes('amr', 'mfa')` would also check the `amr` claim, but it throws an `InvalidTokenError` on failure, which the SDK maps to **`401 invalid_token`**. Step-up failure is not an invalid token — the token is perfectly valid, it just lacks a required authentication factor. The correct status is **`403`** with a code your client can act on to redirect the user for MFA.

| Approach | Status on failure | Correct for step-up? |
|---|---|---|
| `claimIncludes('amr', 'mfa')` | `401 invalid_token` | No |
| Custom middleware returning `403` | `403 mfa_required` | Yes |

## Checking acr Instead of (or in Addition to) amr

Some Auth0 configurations use `acr_values` policies rather than (or alongside) `amr`. Auth0 sets `acr` to the requested policy URI when the policy is satisfied. Treat step-up as complete when **either** signal is present:

```js
const MFA_ACR = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

const requireMfa = (req, res, next) => {
  const { amr, acr } = req.auth?.payload ?? {};
  const mfaCompleted =
    acr === MFA_ACR || (Array.isArray(amr) && amr.includes('mfa'));
  if (!mfaCompleted) {
    return res.status(403).json({ code: 'mfa_required' });
  }
  next();
};
```

## Responding to a 403 on the Client

When your API returns `403 mfa_required`, the **client application** must redirect the user to Auth0 to re-authenticate with a stronger factor and obtain a new access token that carries the MFA claim. That redirect logic belongs in your client SDK (e.g. `auth0-server-python`, `nextjs-auth0`, `express-openid-connect`) — not in this resource server SDK.

See the [Auth0 step-up authentication docs](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication) for how to initiate the step-up redirect from your client application.
