# Direct Public Key Verification Example

Below is an example of how to use the library to verify JWTs with a directly provided public key (no JWKS or discovery):

```js
const { jwtVerifier } = require('access-token-jwt');
// or: import { jwtVerifier } from 'access-token-jwt';

// You could load your public key from a file, environment variable, etc.
// This is just an example of how you'd use it once you have the key
// (could be a CryptoKey, KeyObject, etc.)
const publicKey = getPublicKeyFromSomewhere();

// Set up the verifier with the public key
const verify = jwtVerifier({
  issuer: 'https://your-issuer.example.com/',
  audience: 'https://your-api/',
  secret: publicKey  // Pass the public key directly
});

// Verify a token
try {
  const { payload, header } = await verify(token);
  console.log('Token verified!', payload);
} catch (err) {
  console.error('Token verification failed:', err.message);
}
```

With this approach you can bypass JWKS discovery and validation while still properly verifying tokens signed with asymmetric algorithms.
