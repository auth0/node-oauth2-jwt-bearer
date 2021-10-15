import express = require('express');
import { generateKeyPair, exportJWK } from 'jose';
import type { JWK } from 'jose';
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
  publicJwk = await exportJWK(publicKey);
  privateJwk = await exportJWK(privateKey);
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
