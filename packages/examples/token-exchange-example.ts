/**
 * Comprehensive Token Exchange Examples
 * 
 * This file demonstrates both approaches for token exchange:
 * 1. Direct exchangeToken() function - for manual token exchange
 * 2. req.auth.exchange() method - for Express middleware integration
 */

import express from 'express';
import { auth, exchangeToken } from 'express-oauth2-jwt-bearer';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());

// Rate limiter: max 100 requests per 15 minutes per IP for expensive routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Setup the auth middleware
const authenticateToken = auth({
  issuerBaseURL: 'https://dev-ankita-t.us.auth0.com',
  audience: 'https://api.example.com'
});

// Health check endpoint (no authentication required)
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Token exchange service is running' });
});

// Example 1: Exchange using request auth context (recommended for Express middleware)
// This approach automatically uses the token from the current authenticated request
app.post('/exchange-via-context', authenticateToken, limiter, async (req, res) => {
  try {
    if (!req.auth) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const exchangedToken = await req.auth.exchange({
      tokenEndpoint: 'https://dev-ankita-t.us.auth0.com/oauth/token',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      targetAudience: 'https://api.example.com',
      scope: 'read:data write:data',
    });

    res.json({
      message: 'Token exchanged successfully via auth context',
      exchangedToken,
    });
  } catch (error) {
    console.error('Token exchange failed:', error);
    res.status(500).json({
      error: 'Token exchange failed',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Example 2: Direct token exchange using the exchangeToken function
// This approach allows you to exchange any token manually
app.post('/exchange-direct', authenticateToken, limiter, async (req, res) => {
  try {
    if (!req.auth) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Get the current token from the authenticated request
    const currentToken = req.auth.token;
    
    // Use the direct exchangeToken function - useful for custom scenarios
    const exchangedToken = await exchangeToken(currentToken, {
      tokenEndpoint: 'https://dev-ankita-t.us.auth0.com/oauth/token',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      targetAudience: 'https://api.example.com',
      scope: 'read:data write:data',
    });

    res.json({
      message: 'Token exchanged successfully via direct function',
      exchangedToken,
    });
  } catch (error) {
    const sanitizedErrorMsg = (error instanceof Error ? error.message : String(error)).replace(/[\r\n]+/g, ' ');
    console.error('Token exchange failed:', `[sanitized] ${sanitizedErrorMsg}`);
    res.status(500).json({
      error: 'Token exchange failed',
      details: sanitizedErrorMsg,
    });
  }
});

// Example 3: Exchange a token from request body (demonstrating flexibility of direct function)
// This shows how you can exchange any token, not just the current request's token
app.post('/exchange-any-token', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required in request body' });
    }

    // Use exchangeToken to exchange any provided token
    const exchangedToken = await exchangeToken(token, {
      tokenEndpoint: 'https://dev-ankita-t.us.auth0.com/oauth/token',
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret',
      targetAudience: 'https://api.example.com',
      scope: 'read:data write:data',
    });

    res.json({
      message: 'External token exchanged successfully',
      exchangedToken,
    });
  } catch (error) {
    const sanitizedErrorMsg = (error instanceof Error ? error.message : String(error)).replace(/[\r\n]+/g, ' ');
    console.error('Token exchange failed:', `[sanitized] ${sanitizedErrorMsg}`);
    res.status(500).json({
      error: 'Token exchange failed',
      details: sanitizedErrorMsg,
    });
  }
});

// Demonstration endpoint showing the difference
app.get('/compare-approaches', authenticateToken, async (req, res) => {
  if (!req.auth) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  res.json({
    approaches: {
      authContext: {
        description: 'Uses req.auth.exchange() - automatically uses current request token',
        pros: [
          'Simpler API - no need to extract token manually',
          'Follows express-openid-connect pattern',
          'Integrated with Express middleware',
          'Less error-prone'
        ],
        useCase: 'Best for typical Express apps where you want to exchange the current user\'s token'
      },
      directFunction: {
        description: 'Uses exchangeToken(token, options) - manual token exchange',
        pros: [
          'More flexible - can exchange any token',
          'Can be used outside Express middleware context',
          'Useful for batch processing or admin operations',
          'Direct control over which token to exchange'
        ],
        useCase: 'Best for custom scenarios, background jobs, or when you need to exchange tokens from different sources'
      }
    },
    examples: {
      authContext: 'POST /exchange-via-context (with Authorization header)',
      directFunction: 'POST /exchange-direct (with Authorization header) or POST /exchange-any-token (with token in body)'
    }
  });
});

// Information endpoint for getting tokens (for testing)
app.get('/get-token', (req, res) => {
  res.json({
    message: 'To get tokens for testing, use one of these approaches:',
    approaches: {
      spa: {
        description: 'For Single Page Applications',
        flow: 'Authorization Code with PKCE',
        steps: [
          '1. Configure your Auth0 application as "Single Page Application"',
          '2. Use Auth0 SDK or direct OAuth flow with PKCE',
          '3. Redirect user to authorize endpoint',
          '4. Exchange authorization code for tokens'
        ],
        authUrl: 'https://dev-ankita-t.us.auth0.com/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_CALLBACK&scope=openid%20profile&audience=https://api.example.com&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256'
      },
      m2m: {
        description: 'For Machine-to-Machine Applications',
        flow: 'Client Credentials',
        note: 'Enable "Client Credentials" grant in Auth0 Dashboard > Applications > Your App > Settings > Advanced Settings > Grant Types',
        curl: `curl -X POST https://dev-ankita-t.us.auth0.com/oauth/token \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://api.example.com",
    "grant_type": "client_credentials"
  }'`
      }
    }
  });
});

const port = process.env.PORT || 3006;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log('');
  console.log('Available endpoints:');
  console.log('  GET  /health                 - Health check (no auth)');
  console.log('  GET  /get-token              - Token acquisition info (no auth)');
  console.log('  GET  /compare-approaches     - Compare token exchange methods (requires auth)');
  console.log('  POST /exchange-via-context   - Exchange via req.auth.exchange() (requires auth)');
  console.log('  POST /exchange-direct        - Exchange via exchangeToken() function (requires auth)');
  console.log('  POST /exchange-any-token     - Exchange any token (no auth, token in body)');
  console.log('');
  console.log('Key Differences:');
  console.log('  • req.auth.exchange() - Automatic, uses current request token');
  console.log('  • exchangeToken() - Manual, can exchange any token');
});
