import express = require('express');
import { generateKeyPair } from 'jose/util/generate_key_pair';
import { fromKeyLike, JWK } from 'jose/jwk/from_key_like';
import secret from './secret';

const app = express();

let publicJwk: JWK;
let privateJwk: JWK;

const issuer = 'http://localhost:3000';
const audience = 'https://api';

const keys = async () => {
  if (publicJwk && privateJwk) {
    return { publicJwk, privateJwk };
  }
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  publicJwk = await fromKeyLike(publicKey);
  privateJwk = await fromKeyLike(privateKey);
  return { publicJwk, privateJwk };
};

app.set('views', __dirname);
app.set('view engine', 'ejs');

app.get('/', async (req, res, next) => {
  const { privateJwk } = await keys();
  res.render('playground.ejs', {
    privateJwk,
    secret,
    issuer,
    audience,
  });
});

app.get('/jwks', async (req, res, next) => {
  const { publicJwk } = await keys();
  res.json({ keys: [{ ...publicJwk, alg: 'RS256', kid: '1' }] });
  next();
});

app.get('/.well-known/openid-configuration', async (req, res, next) => {
  res.json({
    issuer,
    jwks_uri: `${issuer}/jwks`,
  });
  next();
});

export default app;
