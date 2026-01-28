# MCD Test Application

Quick test application for the Multiple Custom Domains (MCD) feature.

## Quick Start

### 1. Install dependencies

```bash
npm install express
npm install ../packages/express-oauth2-jwt-bearer
```

### 2. Run tests

#### Test Method 2 (Static Array)
```bash
npm run test:method2
# or
node test-method2.js
```

Open another terminal and test:
```bash
# Health check (should work)
curl http://localhost:3002/health

# Protected endpoint (should return 401)
curl -i http://localhost:3002/protected
```

#### Test Method 3 (Dynamic Resolver)
```bash
npm run test:method3
# or
node test-method3.js
```

Open another terminal and test:
```bash
# Health check (should work)
curl http://localhost:3003/health

# Without tenant ID (should return 401, no resolver logs)
curl -i http://localhost:3003/protected

# With tenant ID (should return 401, but resolver logs will appear!)
curl -i -H "x-tenant-id: tenant-123" http://localhost:3003/protected
```

## What to Expect

### Method 2 Output
When you run Method 2, you should see:
```
✅ Server running on http://localhost:3002

📋 Allowed issuers:
   1. https://tenant1.auth0.com
   2. https://tenant2.auth0.com
   3. https://custom-domain.example.com
```

### Method 3 Output
When you run Method 3, you should see:
```
✅ Server running on http://localhost:3003

📊 Tenant Database (3 tenants):

   tenant-123 → Acme Corp
      ✓ https://acme.auth0.com
      ✓ https://auth.acme.com
```

When you curl with a tenant header, you'll see resolver logs:
```
🔍 Resolver called:
   Token Issuer: (extracted from JWT)
   Tenant ID from header: tenant-123
   📋 Tenant: Acme Corp
   ✅ ALLOWED or ❌ REJECTED
```

## Testing with Real Tokens

To test with actual JWT tokens:

1. Get a token from Auth0 or your identity provider
2. Use it in the Authorization header:

```bash
export TOKEN="eyJhbGc..."

# Test Method 2
curl -H "Authorization: Bearer $TOKEN" http://localhost:3002/protected

# Test Method 3 (with tenant)
curl -H "Authorization: Bearer $TOKEN" \
     -H "x-tenant-id: tenant-123" \
     http://localhost:3003/protected
```

## Success Indicators

✅ **Working correctly if:**
- Servers start without errors
- Health endpoints return 200 OK
- Protected endpoints return 401 Unauthorized (without valid tokens)
- Resolver logs appear when using Method 3 with tenant headers

## Troubleshooting

### Error: Cannot find module 'express-oauth2-jwt-bearer'

Run from the test-mcd-app directory:
```bash
npm install ../packages/express-oauth2-jwt-bearer
```

### Port already in use

Change the PORT variable in the test files or kill the process:
```bash
lsof -ti:3002 | xargs kill -9
```

For more detailed testing instructions, see **TEST_GUIDE.md** in the parent directory.
