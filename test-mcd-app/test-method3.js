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

console.log('\n🧪 MCD Test - Method 3: Dynamic Resolver (Multi-Tenant)\n');
console.log('This tests dynamic issuer validation based on request context.');

// Simulate a database of tenant configurations
const tenantDatabase = {
  'tenant-123': {
    name: 'Acme Corp',
    allowedIssuers: [
      'https://acme.auth0.com',
      'https://auth.acme.com'
    ]
  },
  'tenant-456': {
    name: 'Globex Inc',
    allowedIssuers: [
      'https://globex.auth0.com'
    ]
  },
  'tenant-789': {
    name: 'Initech LLC',
    allowedIssuers: [
      'https://initech.auth0.com',
      'https://sso.initech.com'
    ]
  }
};

// Dynamic resolver function
async function issuerResolver(context) {
  console.log('\n🔍 Resolver called:');
  console.log(`   Token Issuer: ${context.tokenIssuer}`);
  console.log(`   Request URL: ${context.requestUrl}`);
  console.log(`   Request Method: ${context.requestMethod}`);

  // Get tenant ID from header
  const tenantId = context.requestHeaders['x-tenant-id'];
  console.log(`   Tenant ID from header: ${tenantId || '(none)'}`);

  if (!tenantId) {
    console.log(`   ❌ REJECTED: No tenant ID provided\n`);
    return null;
  }

  // Look up tenant configuration
  const tenant = tenantDatabase[tenantId];
  if (!tenant) {
    console.log(`   ❌ REJECTED: Tenant "${tenantId}" not found\n`);
    return null;
  }

  console.log(`   📋 Tenant: ${tenant.name}`);
  console.log(`   📋 Allowed issuers for this tenant:`);
  tenant.allowedIssuers.forEach(iss => console.log(`      - ${iss}`));

  // Check if token issuer is allowed for this tenant
  if (tenant.allowedIssuers.includes(context.tokenIssuer)) {
    const jwksUrl = `${context.tokenIssuer}/.well-known/jwks.json`;
    console.log(`   ✅ ALLOWED: Issuer matches tenant configuration`);
    console.log(`   📄 JWKS URL: ${jwksUrl}\n`);
    return jwksUrl;
  }

  console.log(`   ❌ REJECTED: Issuer not allowed for tenant "${tenant.name}"\n`);
  return null;
}

// Method 3: Dynamic resolver
const authMiddleware = auth({
  issuerResolver,
  audience: 'https://my-api.com',
  issuerCacheTTL: 300000 // 5 minutes (300000ms)
});

app.get('/protected', protectedLimiter, authMiddleware, (req, res) => {
  res.json({
    message: '✅ Access granted!',
    issuer: req.auth.payload.iss,
    audience: req.auth.payload.aud,
    tenant: req.headers['x-tenant-id'],
    user: req.auth.payload.sub
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    method: 'Dynamic Resolver (Method 3)',
    tenants: Object.keys(tenantDatabase).length
  });
});

const PORT = 3003;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`\n📊 Tenant Database (${Object.keys(tenantDatabase).length} tenants):`);
  Object.entries(tenantDatabase).forEach(([id, config]) => {
    console.log(`\n   ${id} → ${config.name}`);
    config.allowedIssuers.forEach(issuer => {
      console.log(`      ✓ ${issuer}`);
    });
  });
  console.log(`\n💡 Test commands:`);
  console.log(`   Health check:  curl http://localhost:${PORT}/health`);
  console.log(`   Without tenant: curl http://localhost:${PORT}/protected`);
  console.log(`   With tenant:   curl -H "x-tenant-id: tenant-123" http://localhost:${PORT}/protected`);
  console.log(`   With token:    curl -H "Authorization: Bearer YOUR_TOKEN" -H "x-tenant-id: tenant-123" http://localhost:${PORT}/protected`);
  console.log(`\n⏸️  Press Ctrl+C to stop\n`);
});
