import { auth } from 'express-oauth2-jwt-dpop';
import express = require('express');
import cors = require('cors');
import { Handler } from 'express';

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
    allowedHeaders: ['Authorization', 'DPoP'],
    exposedHeaders: ['WWW-Authenticate'],
  })
);

app.get('/auth', requiresAuth, handler);

export default app;
