## Hierarchy

- *JwtVerifierOptions*

  ↳ **WithoutDiscovery**

## Table of contents

### Properties

- [agent](withoutdiscovery.md#agent)
- [audience](withoutdiscovery.md#audience)
- [clockTolerance](withoutdiscovery.md#clocktolerance)
- [cooldownDuration](withoutdiscovery.md#cooldownduration)
- [issuer](withoutdiscovery.md#issuer)
- [jwksUri](withoutdiscovery.md#jwksuri)
- [maxTokenAge](withoutdiscovery.md#maxtokenage)
- [strict](withoutdiscovery.md#strict)
- [timeoutDuration](withoutdiscovery.md#timeoutduration)
- [validators](withoutdiscovery.md#validators)

## Properties

### agent

• `Optional` **agent**: *Agent* \| *Agent*

An instance of http.Agent or https.Agent to pass to the http.get or
https.get method options. Use when behind an http(s) proxy.

Inherited from: JwtVerifierOptions.agent

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:15

___

### audience

• **audience**: *string* \| *string*[]

Expected JWT "aud" (Audience) Claim value(s).

Inherited from: JwtVerifierOptions.audience

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:10

___

### clockTolerance

• `Optional` **clockTolerance**: *number*

Clock tolerance (in secs) used when validating the `exp` and `iat` claim.
Defaults to 5 secs.

Inherited from: JwtVerifierOptions.clockTolerance

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:51

___

### cooldownDuration

• `Optional` **cooldownDuration**: *number*

Duration in ms for which no more HTTP requests to the JWKS Uri endpoint
will be triggered after a previous successful fetch.
Default is 30000.

Inherited from: JwtVerifierOptions.cooldownDuration

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:21

___

### issuer

• **issuer**: *string*

Expected JWT "iss" (Issuer) Claim value.

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:78

___

### jwksUri

• **jwksUri**: *string*

Url for the authorization server's JWKS to find the public key to verify
an Access Token JWT.

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:83

___

### maxTokenAge

• `Optional` **maxTokenAge**: *number*

Maximum age (in secs) from when a token was issued to when it con no longer
be accepted.

Inherited from: JwtVerifierOptions.maxTokenAge

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:56

___

### strict

• `Optional` **strict**: *boolean*

If set to `true` the token validation will strictly follow
'JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens'
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-access-token-jwt-12
Defaults to false.

Inherited from: JwtVerifierOptions.strict

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:63

___

### timeoutDuration

• `Optional` **timeoutDuration**: *number*

Timeout in ms for the HTTP request. When reached the request will be
aborted.
Default is 5000.

Inherited from: JwtVerifierOptions.timeoutDuration

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:27

___

### validators

• `Optional` **validators**: *Partial*<[*Validators*](validators.md)\>

Pass in custom validators to override the existing validation behavior on
standard claims or add new validation behavior on custom claims.

```js
 {
   validators: {
     // Disable issuer validation by passing `false`
     iss: false,
     // Add validation for a custom claim to equal a passed in string
     org_id: 'my_org_123'
     // Add validation for a custom claim, by passing in a function that
     // implements [FunctionValidator](../types/functionvalidator.md)}
     roles: (roles, claims, header) => roles.includes('editor') && claims.isAdmin
   }
 }
```

Inherited from: JwtVerifierOptions.validators

Defined in: packages/access-token-jwt/dist/jwt-verifier.d.ts:46
