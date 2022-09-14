# express-oauth2-jwt-dpop

Authentication middleware for Express.js that validates JWT DPoP Access Tokens.

# Install
```bash
npm install https://github.com/auth0/node-oauth2-jwt-bearer/raw/dpop/express-oauth2-jwt-dpop-0.0.0-alpha.1.tgz
```

## Getting started

The library requires [issuerBaseURL](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/authoptions.html#issuerbaseurl) and [audience](https://auth0.github.io/node-oauth2-jwt-bearer/interfaces/authoptions.html#audience), which can be configured with environmental variables:

```shell
ISSUER_BASE_URL=https://YOUR_ISSUER_DOMAIN
AUDIENCE=https://my-api.com
```

```js
const { auth } = require('express-oauth2-jwt-dpop');
app.use(auth());
```

... or in the library initialization:

```js
const { auth } = require('express-oauth2-jwt-dpop');
app.use(
    auth({
      issuerBaseURL: 'https://YOUR_ISSUER_DOMAIN',
      audience: 'https://my-api.com'
    })
);
```

## Develop

```bash
# From monorepo route
git checkout dpop
# Hack, hack, hack
npm build
# Bump the package version and update the install instructions
npm pack --workspace=packages/express-oauth2-jwt-dpop
# Delete old tgz
# Push to git
```

### To run test app

```bash
# From monorepo route
git checkout dpop
npm install
npm build
npm run dev --workspace=packages/examples
# Visit http://localhost:3000
```
