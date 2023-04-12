import {
  auth,
  requiredScopes,
  scopeIncludesAny,
  claimEquals,
  claimIncludes,
  requiredAcrValues,
  requiredMaxAge,
} from 'express-oauth2-jwt-bearer';
import express = require('express');
import cors = require('cors');
import { Handler } from 'express';
import secret from './secret';

const app = express();
const issuerBaseURL = 'http://localhost:3000';
const audience = 'https://api';
const handler: Handler = (req, res) => {
  res.json({ msg: 'Hello World!' });
};
const requiresAuth = auth({ issuerBaseURL, audience });

app.use(
  cors({
    origin: issuerBaseURL,
    allowedHeaders: ['Authorization'],
    exposedHeaders: ['WWW-Authenticate'],
  })
);

app.get('/auth', requiresAuth, handler);

app.get('/scope', requiresAuth, requiredScopes('read:msg'), handler);

app.get(
  '/any-scope',
  requiresAuth,
  scopeIncludesAny(['read:msg', 'audit:read']),
  handler
);

app.get(
  '/acr',
  requiresAuth,
  requiredAcrValues(['myAcr', 'anotherAcr']),
  handler
);

app.get('/max-age', requiresAuth, requiredMaxAge(10), handler);

app.get('/claim-equals', requiresAuth, claimEquals('foo', 'bar'), handler);

app.get(
  '/claim-includes',
  requiresAuth,
  claimIncludes('foo', 'bar', 'baz'),
  handler
);

app.get(
  '/custom',
  auth({ issuerBaseURL, audience, validators: { iss: false } }),
  handler
);

app.get('/strict', auth({ issuerBaseURL, audience, strict: true }), handler);

app.get(
  '/symmetric',
  auth({ secret, issuer: issuerBaseURL, audience, tokenSigningAlg: 'HS256' }),
  handler
);

export default app;
