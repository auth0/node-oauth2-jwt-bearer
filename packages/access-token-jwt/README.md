# access-token-jwt

_This package is not published_

Verfies and decodes Access Token JWTs loosley following [draft-ietf-oauth-access-token-jwt-12](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-12)

## Features

- JWT verification with JWKS discovery
- Support for direct public key verification (no JWKS required)
- Symmetric algorithm support (HS256, HS384, HS512)
- Asymmetric algorithm support (RS256, RS384, etc.)
- Customizable claim validation
