# oauth2-jwt-bearer

Monorepo for `oauth2-jwt-bearer`. Contains the following packages:

- `oauth2-bearer` (not published) Gets Bearer tokens from a request and issues errors per https://tools.ietf.org/html/rfc6750
- `access-token-jwt` (not published) Verfies and decodes Access Token JWTs loosley following https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-12
- [express-oauth2-jwt-bearer](#express-oauth2-jwt-bearer) Authentication middleware for Express.js that validates JWT bearer access tokens

## express-oauth2-jwt-bearer

### Install

`npm install express-oauth2-jwt-bearer`

### Usage

```js
import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';

const app = express();

app.use(
    auth({
      issuerBaseURL: 'https://issuer.example.com/',
      audience: 'https://api/',
    })
);

app.get('/api/me', (req, res) => {
  res.json(req.auth);
});
```

## Development

This package uses npm workspaces. You must have `npm >= @7.7` to develop this package

To run a command in the context of a workspace from the root use the `--workspace` or `--workspaces` arguments.

```shell
# build oauth2-bearer
npm run build --workspace=oauth2-bearer

# run all tests
npm test --workspaces
```

You can't yet run `npm install` with the `workspace` flag, so to install something - don't run install from the workspace, instead from the root run:

```sh
# to install 'jest' to 'packages/oauth2-bearer'
npm install:workspace -- packages/oauth2-bearer jest
```
