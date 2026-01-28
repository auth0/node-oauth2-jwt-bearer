const express = require('express');
const { auth } = require('express-oauth2-jwt-bearer');

const app = express();

console.log('\n🧪 MCD Test - Method 2: Static Array of Issuers\n');
console.log('This tests the ability to accept tokens from multiple predefined issuers.');

// Method 2: Static array of allowed issuers
app.use(auth({
  issuers: [
    'https://tenant1.auth0.com',
    'https://tenant2.auth0.com',
    'https://custom-domain.example.com'
  ],
  audience: 'https://my-api.com'
}));

app.get('/protected', (req, res) => {
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
