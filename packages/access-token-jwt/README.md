# access-token-jwt

_This package is not published_

Verfies and decodes Access Token JWTs loosley following [draft-ietf-oauth-access-token-jwt-12](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-12)

## Features

- JWT verification with JWKS discovery (OAuth2/OpenID Connect)
- Direct public key verification without JWKS (KeyLike objects)
- Symmetric algorithm support (HS256, HS384, HS512)
- Asymmetric algorithm support (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES256K, ES384, ES512, EdDSA)
- DPoP (Demonstration of Proof-of-Possession) support
- Customizable claim validation
- Clock tolerance and token age validation
