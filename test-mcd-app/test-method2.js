const express = require('express');
const { auth } = require('express-oauth2-jwt-bearer');
const rateLimit = require('express-rate-limit');

const app = express();

// Rate limiter for protected routes
const protectedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

console.log('\n🧪 MCD Test - Method 2: Static Array of Issuers\n');
console.log('This tests the ability to accept tokens from multiple predefined issuers.');

// Method 2: Static array of allowed issuers
const authMiddleware = auth({
  issuers: [
    'https://tenant1.auth0.com',
    'https://tenant2.auth0.com',
    'https://custom-domain.example.com'
  ],
  audience: 'https://my-api.com'
});

app.get('/protected', protectedLimiter, authMiddleware, (req, res) => {
  res.json({
    message: '✅ Access granted!',
    issuer: req.auth.payload.iss,
    audience: req.auth.payload.aud,
    user: req.auth.payload.sub
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', method: 'Static Array (Method 2)' });
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`\n📋 Allowed issuers:`);
  console.log(`   1. https://tenant1.auth0.com`);
  console.log(`   2. https://tenant2.auth0.com`);
  console.log(`   3. https://custom-domain.example.com`);
  console.log(`\n🔒 Tokens with other issuers will be rejected (SSRF prevention)`);
  console.log(`\n💡 Test commands:`);
  console.log(`   Health check:  curl http://localhost:${PORT}/health`);
  console.log(`   Protected:     curl http://localhost:${PORT}/protected`);
  console.log(`   With token:    curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:${PORT}/protected`);
  console.log(`\n⏸️  Press Ctrl+C to stop\n`);
});
