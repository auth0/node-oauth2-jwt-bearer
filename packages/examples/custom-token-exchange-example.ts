// Custom Token Exchange Example
// This example demonstrates how to use the RFC 8693 compliant custom token exchange
// middleware with Express.js and Auth0.

import express, { Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import {
  customTokenExchange,
  auth0TokenExchange,
  defaultTokenExchangeHandler,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPES,
  TokenExchangeHandler,
  TokenExchangeRequest,
  TokenExchangeResponse,
  TokenValidationOptions,
  ResponseOptions,
  ProviderConfig,
  AudienceScopeMapping,
  TokenExchangeError,
  InvalidSubjectTokenError,
  UnsupportedTokenTypeError
} from '../express-oauth2-jwt-bearer/src/custom-token-exchange';
import { JWTPayload } from 'access-token-jwt';

// Configuration
const config = {
  issuer: process.env.AUTH0_ISSUER || 'https://your-domain.auth0.com/',
  audience: process.env.AUTH0_AUDIENCE || 'your-api-identifier',
  secret: process.env.JWT_SECRET || 'your-jwt-secret',
  port: process.env.PORT || 3000
};

const app = express();

// Middleware for parsing JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * Example 1: Basic Token Exchange with Default Handler
 * 
 * This example uses the default token exchange handler which creates
 * a new token with modified audience and scope claims.
 */
app.post('/oauth/token/basic', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256']
}));

/**
 * Example 2: Custom Token Exchange Handler
 * 
 * This example shows how to implement custom business logic
 * for token exchange scenarios.
 */
const customExchangeHandler: TokenExchangeHandler = async (
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest,
  originalRequest: Request
): Promise<TokenExchangeResponse> => {
  console.log('Processing token exchange for user:', subjectPayload.sub);
  console.log('Requested audience:', request.audience);
  console.log('Requested scope:', request.scope);

  // Custom business logic - validate user permissions
  const userHasPermission = await validateUserPermissions(
    subjectPayload.sub as string,
    request.scope || ''
  );

  if (!userHasPermission) {
    throw new Error('User does not have required permissions for requested scope');
  }

  // Create enhanced payload with additional claims
  // Exclude exp, iat from original payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...subjectPayloadWithoutTiming } = subjectPayload;
  const newPayload: JWTPayload = {
    ...subjectPayloadWithoutTiming,
    aud: request.audience || subjectPayload.aud,
    scope: request.scope || subjectPayload.scope,
    iat: Math.floor(Date.now() / 1000),
    // Add custom claims
    exchanged_at: new Date().toISOString(),
    exchange_type: 'custom_exchange',
    original_audience: subjectPayload.aud,
    permissions: await getUserPermissions(subjectPayload.sub as string)
  };

  // Sign the new token - use expiresIn option instead of exp in payload
  const accessToken = jwt.sign(newPayload, config.secret, {
    algorithm: 'HS256',
    expiresIn: '2h'
  });

  return {
    access_token: accessToken,
    issued_token_type: request.requested_token_type || TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 7200,
    scope: request.scope,
    // Add custom response fields
    refresh_token: await generateRefreshToken(subjectPayload.sub as string)
  };
};

app.post('/oauth/token/custom', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256'],
  exchangeHandler: customExchangeHandler,
  tokenValidation: {
    clockTolerance: 60, // 1 minute tolerance
    customValidation: (payload: JWTPayload) => {
      // Custom validation - ensure token has required claims
      return !!(payload.sub && payload.aud && payload.scope);
    }
  },
  responseOptions: {
    additionalFields: {
      token_source: 'custom_exchange_api'
    }
  }
}));

/**
 * Example 3: Auth0-Compatible Token Exchange
 * 
 * This example uses the pre-configured Auth0-compatible middleware
 * with sensible defaults for Auth0 environments.
 */
app.post('/oauth/token/auth0', auth0TokenExchange(
  config.issuer,
  config.audience,
  config.secret
));

/**
 * Example 4: Token Exchange with Resource-Specific Logic
 * 
 * This example demonstrates handling different resources
 * with specific business logic.
 */
const resourceSpecificHandler: TokenExchangeHandler = async (
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest,
  originalRequest?: Request
): Promise<TokenExchangeResponse> => {
  const resource = request.resource;
  
  // Different logic based on target resource
  switch (resource) {
    case 'https://api.payments.example.com':
      return await handlePaymentsTokenExchange(subjectPayload, request);
    case 'https://api.users.example.com':
      return await handleUsersTokenExchange(subjectPayload, request);
    case 'https://api.analytics.example.com':
      return await handleAnalyticsTokenExchange(subjectPayload, request);
    default:
      return await handleDefaultTokenExchange(subjectPayload, request);
  }
};

app.post('/oauth/token/resource-specific', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256'],
  exchangeHandler: resourceSpecificHandler
}));

/**
 * Example 5: Token Exchange with Delegation (Actor Token)
 * 
 * This example shows how to handle token exchange with actor tokens
 * for delegation scenarios.
 */
const delegationHandler: TokenExchangeHandler = async (
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest,
  originalRequest?: Request
): Promise<TokenExchangeResponse> => {
  let finalPayload = { ...subjectPayload };

  // Handle actor token for delegation scenarios
  if (request.actor_token && request.actor_token_type) {
    console.log('Processing delegation with actor token');
    
    try {
      const actorPayload = jwt.verify(request.actor_token, config.secret) as JWTPayload;
      
      // Validate delegation permissions
      const canDelegate = await validateDelegationPermissions(
        actorPayload.sub as string,
        subjectPayload.sub as string,
        request.scope || ''
      );

      if (!canDelegate) {
        throw new Error('Actor does not have delegation permissions');
      }

      // Add actor information to the new token
      finalPayload = {
        ...finalPayload,
        act: {
          sub: actorPayload.sub,
          iss: actorPayload.iss
        },
        delegation_chain: [
          { actor: actorPayload.sub, delegated_at: new Date().toISOString() }
        ]
      };
    } catch (error) {
      throw new Error(`Invalid actor token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Create the new token with delegation information
  // Exclude exp, iat from payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...payloadWithoutTiming } = finalPayload;
  const newToken = jwt.sign({
    ...payloadWithoutTiming,
    aud: request.audience || finalPayload.aud,
    scope: request.scope || finalPayload.scope,
    iat: Math.floor(Date.now() / 1000)
  }, config.secret, {
    expiresIn: '1h'
  });

  return {
    access_token: newToken,
    issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: request.scope
  };
};

app.post('/oauth/token/delegation', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256'],
  exchangeHandler: delegationHandler
}));

/**
 * Example 6: Error Handling and Logging
 */
app.post('/oauth/token/monitored', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256'],
  exchangeHandler: async (subjectPayload: JWTPayload, request: TokenExchangeRequest, originalRequest?: Request) => {
    // Log the token exchange attempt
    console.log('Token exchange attempt:', {
      user: subjectPayload.sub,
      audience: request.audience,
      scope: request.scope,
      timestamp: new Date().toISOString(),
      ip: (originalRequest as any).ip,
      userAgent: (originalRequest as any).get('User-Agent')
    });

    try {
      const result = await customExchangeHandler(subjectPayload, request, originalRequest!);
      
      // Log successful exchange
      console.log('Token exchange successful:', {
        user: subjectPayload.sub,
        newAudience: request.audience,
        expiresIn: result.expires_in
      });

      return result;
    } catch (error) {
      // Enhanced error handling with specific error types
      if (error instanceof TokenExchangeError) {
        console.error('Token exchange error:', {
          user: subjectPayload.sub,
          errorType: error.name,
          errorCode: error.error,
          message: error.message,
          timestamp: new Date().toISOString()
        });
      } else if (error instanceof InvalidSubjectTokenError) {
        console.error('Invalid subject token:', {
          user: subjectPayload.sub,
          message: error.message,
          timestamp: new Date().toISOString()
        });
      } else if (error instanceof UnsupportedTokenTypeError) {
        console.error('Unsupported token type:', {
          user: subjectPayload.sub,
          message: error.message,
          timestamp: new Date().toISOString()
        });
      } else {
        console.error('Token exchange failed:', {
          user: subjectPayload.sub,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
      throw error;
    }
  }
}));

/**
 * Example 7: Multi-Provider Support with Advanced Configuration
 * 
 * This example demonstrates advanced configuration with multiple identity providers,
 * audience/scope mapping, and RS256 key pairs.
 */
const advancedProviderConfig: ProviderConfig[] = [
  {
    name: 'auth0',
    issuerPattern: /\.auth0\.com\/$/,
    algorithms: ['RS256'],
    jwksUri: 'https://your-domain.auth0.com/.well-known/jwks.json'
  },
  {
    name: 'google',
    issuerPattern: /accounts\.google\.com/,
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    algorithms: ['RS256']
  },
  {
    name: 'custom-idp',
    issuerPattern: /custom-idp\.example\.com/,
    algorithms: ['HS256'],
    customValidator: async (token: string) => {
      // Custom validation logic for your identity provider
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.custom_claim) {
        throw new Error('Missing required custom claim');
      }
      return decoded;
    }
  }
];

const audienceScopeMapping: AudienceScopeMapping[] = [
  {
    sourceAudience: /external-api\.com/,
    targetAudience: 'https://internal-api.example.com',
    scopeMapping: {
      'read': ['internal:read', 'internal:list'],
      'write': ['internal:write', 'internal:update'],
      'admin': ['internal:admin', 'internal:delete']
    },
    additionalClaims: {
      mapped_from: 'external_provider',
      internal_permissions: ['mapped_user']
    }
  }
];

const advancedTokenValidation: TokenValidationOptions = {
  clockTolerance: 300, // 5 minutes tolerance
  ignoreExpiration: false,
  ignoreNotBefore: false,
  maxAge: '24h',
  customValidation: (payload: any) => {
    // Ensure required claims are present
    return !!(payload.sub && payload.aud && payload.iat);
  },
  useIntrospection: false
};

const enhancedResponseOptions: ResponseOptions = {
  issuedTokenType: TOKEN_TYPES.ACCESS_TOKEN,
  expiresIn: 7200, // 2 hours
  additionalFields: {
    token_source: 'advanced_exchange_api',
    exchange_version: '2.0',
    capabilities: ['delegation', 'multi_provider', 'scope_mapping']
  },
  providerAdditionalFields: {
    'auth0': {
      connection: 'Username-Password-Authentication',
      auth0_client_id: 'mapped_client_id'
    },
    'google': {
      google_workspace: true,
      domain: 'example.com'
    }
  }
};

app.post('/oauth/token/advanced', customTokenExchange({
  issuer: config.issuer,
  audience: config.audience,
  secret: config.secret,
  algorithms: ['HS256', 'RS256'],
  supportedTokenTypes: [
    TOKEN_TYPES.ACCESS_TOKEN,
    TOKEN_TYPES.ID_TOKEN,
    TOKEN_TYPES.JWT,
    TOKEN_TYPES.SAML2
  ],
  providers: advancedProviderConfig,
  audienceScopeMapping: audienceScopeMapping,
  enableActorTokens: true,
  tokenValidation: advancedTokenValidation,
  responseOptions: enhancedResponseOptions,
  exchangeHandler: async (
    subjectPayload: JWTPayload,
    request: TokenExchangeRequest,
    originalRequest: Request
  ): Promise<TokenExchangeResponse> => {
    try {
      // Use the default handler with all the advanced configurations
      return await defaultTokenExchangeHandler(
        subjectPayload,
        request,
        originalRequest
      );
    } catch (error) {
      // Custom error handling for advanced scenarios
      if (error instanceof InvalidSubjectTokenError) {
        throw new TokenExchangeError(
          `Advanced validation failed: ${error.message}`,
          'invalid_grant'
        );
      }
      throw error;
    }
  }
}));

// Utility functions for the examples
async function validateUserPermissions(userId: string, scope: string): Promise<boolean> {
  // Mock implementation - replace with actual permission validation
  console.log(`Validating permissions for user ${userId} with scope ${scope}`);
  return true; // Always return true for demo purposes
}

async function getUserPermissions(userId: string): Promise<string[]> {
  // Mock implementation - replace with actual permission retrieval
  return ['read:profile', 'write:profile', 'read:data'];
}

async function generateRefreshToken(userId: string): Promise<string> {
  // Mock implementation - replace with actual refresh token generation
  return jwt.sign({ sub: userId, type: 'refresh' }, config.secret, { expiresIn: '30d' });
}

async function validateDelegationPermissions(
  actorId: string,
  subjectId: string,
  scope: string
): Promise<boolean> {
  // Mock implementation - replace with actual delegation validation
  console.log(`Validating delegation: actor ${actorId} for subject ${subjectId} with scope ${scope}`);
  return true;
}

// Resource-specific handlers
async function handlePaymentsTokenExchange(
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest
): Promise<TokenExchangeResponse> {
  // Payments-specific logic
  // Exclude exp, iat from payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...payloadWithoutTiming } = subjectPayload;
  const enhancedPayload = {
    ...payloadWithoutTiming,
    aud: 'https://api.payments.example.com',
    scope: 'payments:read payments:write',
    payment_permissions: ['view_transactions', 'create_payment']
  };

  const token = jwt.sign(enhancedPayload, config.secret, { expiresIn: '1h' });
  
  return {
    access_token: token,
    issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'payments:read payments:write'
  };
}

async function handleUsersTokenExchange(
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest
): Promise<TokenExchangeResponse> {
  // Users-specific logic
  // Exclude exp, iat from payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...payloadWithoutTiming } = subjectPayload;
  const enhancedPayload = {
    ...payloadWithoutTiming,
    aud: 'https://api.users.example.com',
    scope: 'users:read users:write',
    user_permissions: ['view_profiles', 'edit_profile']
  };

  const token = jwt.sign(enhancedPayload, config.secret, { expiresIn: '2h' });
  
  return {
    access_token: token,
    issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 7200,
    scope: 'users:read users:write'
  };
}

async function handleAnalyticsTokenExchange(
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest
): Promise<TokenExchangeResponse> {
  // Analytics-specific logic
  // Exclude exp, iat from payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...payloadWithoutTiming } = subjectPayload;
  const enhancedPayload = {
    ...payloadWithoutTiming,
    aud: 'https://api.analytics.example.com',
    scope: 'analytics:read',
    analytics_permissions: ['view_reports', 'export_data']
  };

  const token = jwt.sign(enhancedPayload, config.secret, { expiresIn: '4h' });
  
  return {
    access_token: token,
    issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 14400,
    scope: 'analytics:read'
  };
}

async function handleDefaultTokenExchange(
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest
): Promise<TokenExchangeResponse> {
  // Default logic for unknown resources
  // Exclude exp, iat from payload to avoid conflicts with jwt.sign options
  const { exp, iat, ...payloadWithoutTiming } = subjectPayload;
  const token = jwt.sign({
    ...payloadWithoutTiming,
    aud: request.audience || subjectPayload.aud,
    scope: request.scope || subjectPayload.scope,
    iat: Math.floor(Date.now() / 1000)
  }, config.secret, {
    expiresIn: '1h'
  });

  return {
    access_token: token,
    issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: request.scope
  };
}

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  (res as any).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Example client endpoint to test token exchange
app.post('/test-exchange', async (req: Request, res: Response) => {
  try {
    // Create a test subject token
    const testPayload = {
      iss: config.issuer,
      aud: config.audience,
      sub: 'test-user-123',
      scope: 'read write',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    };

    const subjectToken = jwt.sign(testPayload, config.secret);

    // Example token exchange request
    const exchangeRequest = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: subjectToken,
      subject_token_type: TOKEN_TYPES.ACCESS_TOKEN,
      audience: 'https://api.example.com',
      scope: 'read:data write:data'
    };

    (res as any).json({
      message: 'Test token exchange request',
      request: exchangeRequest,
      instructions: 'Send a POST request to one of the /oauth/token/* endpoints with this request body'
    });
  } catch (error) {
    (res as any).status(500).json({
      error: 'Failed to create test request',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Start the server
const server = app.listen(config.port, () => {
  console.log(`Custom Token Exchange Example Server running on port ${config.port}`);
  console.log('Available endpoints:');
  console.log('  POST /oauth/token/basic - Basic token exchange');
  console.log('  POST /oauth/token/custom - Custom token exchange with business logic');
  console.log('  POST /oauth/token/auth0 - Auth0-compatible token exchange');
  console.log('  POST /oauth/token/resource-specific - Resource-specific token exchange');
  console.log('  POST /oauth/token/delegation - Token exchange with delegation');
  console.log('  POST /oauth/token/monitored - Token exchange with logging');
  console.log('  POST /test-exchange - Generate test token exchange request');
  console.log('  GET /health - Health check');
});

export default app;
