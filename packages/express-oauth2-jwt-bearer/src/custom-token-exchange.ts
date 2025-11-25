// RFC 8693 Token Exchange Implementation for Auth0
// This implementation follows the OAuth 2.0 Token Exchange specification (RFC 8693)
// and Auth0's guidelines for secure token exchange.

import { Handler, Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { JWTPayload } from 'access-token-jwt';
import fetch from 'node-fetch';

// Extend Express Request interface for token exchange
declare global {
  namespace Express {
    interface Request {
      tokenExchangeOptions?: CustomTokenExchangeOptions;
      tokenExchange?: {
        subjectPayload: JWTPayload;
        exchangeRequest: TokenExchangeRequest;
        actorInfo?: ActorTokenInfo;
        providerName?: string;
      };
    }
  }
}

/**
 * RFC 8693 Token Exchange Grant Type
 */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * RFC 8693 Token Types
 */
export const TOKEN_TYPES = {
  ACCESS_TOKEN: 'urn:ietf:params:oauth:token-type:access_token',
  REFRESH_TOKEN: 'urn:ietf:params:oauth:token-type:refresh_token',
  ID_TOKEN: 'urn:ietf:params:oauth:token-type:id_token',
  SAML2: 'urn:ietf:params:oauth:token-type:saml2',
  JWT: 'urn:ietf:params:oauth:token-type:jwt'
} as const;

/**
 * Supported Identity Provider configurations
 */
export interface ProviderConfig {
  /** Provider name */
  name: string;
  /** Issuer pattern to match */
  issuerPattern: RegExp;
  /** JWKS URI for token validation */
  jwksUri?: string;
  /** Introspection endpoint */
  introspectionEndpoint?: string;
  /** Supported algorithms */
  algorithms: string[];
  /** Custom validation function */
  customValidator?: (token: string) => Promise<JWTPayload>;
}

/**
 * Key pair configuration for signing
 */
export interface KeyPairConfig {
  /** Private key for signing (PEM format) */
  privateKey: string;
  /** Public key for verification (PEM format) */
  publicKey: string;
  /** Key ID */
  kid?: string;
  /** Algorithm to use */
  algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
}

/**
 * Audience and scope mapping configuration
 */
export interface AudienceScopeMapping {
  /** Source audience pattern */
  sourceAudience: RegExp | string;
  /** Target audience */
  targetAudience: string;
  /** Scope mapping rules */
  scopeMapping?: {
    [sourceScope: string]: string | string[];
  };
  /** Additional claims to add */
  additionalClaims?: Record<string, unknown>;
}

/**
 * Configuration options for custom token exchange
 */
export interface CustomTokenExchangeOptions {
  /** The issuer URL for token validation */
  issuer: string;
  /** The audience for token validation */
  audience: string;
  /** Secret or public key for JWT verification */
  secret?: string;
  /** Key pair configuration for RS256 signing */
  keyPair?: KeyPairConfig;
  /** Algorithm used for JWT signing/verification */
  algorithms?: string[];
  /** Supported token types */
  supportedTokenTypes?: string[];
  /** Provider configurations for multi-IdP support */
  providers?: ProviderConfig[];
  /** Audience and scope mapping rules */
  audienceScopeMapping?: AudienceScopeMapping[];
  /** Custom token exchange handler */
  exchangeHandler?: TokenExchangeHandler;
  /** Token validation options */
  tokenValidation?: TokenValidationOptions;
  /** Response customization options */
  responseOptions?: ResponseOptions;
  /** Enable actor token support for delegation */
  enableActorTokens?: boolean;
  /** Token introspection configuration */
  introspection?: {
    endpoint: string;
    clientId: string;
    clientSecret: string;
  };
}

/**
 * Token validation configuration
 */
export interface TokenValidationOptions {
  /** Clock tolerance in seconds */
  clockTolerance?: number;
  /** Whether to ignore expiration */
  ignoreExpiration?: boolean;
  /** Whether to ignore not before */
  ignoreNotBefore?: boolean;
  /** Maximum token age in seconds */
  maxAge?: string | number;
  /** Custom claims validation */
  customValidation?: (payload: JWTPayload) => boolean;
  /** Use introspection for external tokens */
  useIntrospection?: boolean;
}

/**
 * Response customization options
 */
export interface ResponseOptions {
  /** Custom token type for issued token */
  issuedTokenType?: string;
  /** Custom expires_in value */
  expiresIn?: number;
  /** Additional response fields */
  additionalFields?: Record<string, unknown>;
  /** Provider-specific additional fields */
  providerAdditionalFields?: {
    [providerName: string]: Record<string, unknown>;
  };
}

/**
 * Token exchange request parameters (RFC 8693)
 */
export interface TokenExchangeRequest {
  /** Grant type - must be token-exchange */
  grant_type: string;
  /** The subject token to be exchanged */
  subject_token: string;
  /** Type of the subject token */
  subject_token_type: string;
  /** The target audience for the new token */
  audience?: string;
  /** The scope of the requested token */
  scope?: string;
  /** Type of the requested token */
  requested_token_type?: string;
  /** The target resource for the new token */
  resource?: string;
  /** Actor token for delegation scenarios */
  actor_token?: string;
  /** Type of the actor token */
  actor_token_type?: string;
}

/**
 * Token exchange response (RFC 8693)
 */
export interface TokenExchangeResponse {
  /** The issued access token */
  access_token: string;
  /** Type of the issued token */
  issued_token_type: string;
  /** Token type (typically "Bearer") */
  token_type: string;
  /** Token expiration time in seconds */
  expires_in?: number;
  /** Scope of the issued token */
  scope?: string;
  /** Refresh token (optional) */
  refresh_token?: string;
}

/**
 * Actor token information for delegation scenarios
 */
export interface ActorTokenInfo {
  /** Actor token payload */
  payload: JWTPayload;
  /** Actor token type */
  tokenType: string;
}

/**
 * Custom token exchange handler function type
 */
export type TokenExchangeHandler = (
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest,
  originalRequest: Request,
  actorInfo?: ActorTokenInfo
) => Promise<TokenExchangeResponse> | TokenExchangeResponse;

/**
 * Extended Express Request interface for token exchange
 */
declare global {
  namespace Express {
    interface Request {
      tokenExchange?: {
        subjectPayload: JWTPayload;
        exchangeRequest: TokenExchangeRequest;
        actorInfo?: ActorTokenInfo;
        providerName?: string;
      };
    }
  }
}

/**
 * Default provider configurations
 */
const DEFAULT_PROVIDERS: ProviderConfig[] = [
  {
    name: 'auth0',
    issuerPattern: /^https:\/\/[a-zA-Z0-9-]+\.auth0\.com\/?$/,
    algorithms: ['RS256'],
    jwksUri: undefined // Will be constructed from issuer
  },
  {
    name: 'google',
    issuerPattern: /^https:\/\/accounts\.google\.com\/?$/,
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    algorithms: ['RS256']
  },
  {
    name: 'cognito',
    issuerPattern: /^https:\/\/cognito-idp\.[a-zA-Z0-9-]+\.amazonaws\.com\/[a-zA-Z0-9-_]+\/?$/,
    algorithms: ['RS256']
  },
  {
    name: 'azure',
    issuerPattern: /^https:\/\/login\.microsoftonline\.com\/[a-fA-F0-9-]+\/?$/,
    algorithms: ['RS256']
  }
];

/**
 * Detect provider from token issuer
 */
function detectProvider(issuer: string, providers: ProviderConfig[]): ProviderConfig | null {
  for (const provider of providers) {
    if (provider.issuerPattern.test(issuer)) {
      return provider;
    }
  }
  return null;
}

/**
 * Validate subject token type support
 */
function validateTokenTypeSupport(
  tokenType: string,
  supportedTypes: string[] = [TOKEN_TYPES.JWT, TOKEN_TYPES.ACCESS_TOKEN, TOKEN_TYPES.ID_TOKEN, TOKEN_TYPES.SAML2]
): void {
  if (!supportedTypes.includes(tokenType)) {
    throw new UnsupportedTokenTypeError(tokenType);
  }
}

/**
 * Validate token via introspection endpoint
 */
async function validateTokenViaIntrospection(
  token: string,
  introspectionConfig: NonNullable<CustomTokenExchangeOptions['introspection']>
): Promise<JWTPayload> {
  const response = await fetch(introspectionConfig.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${Buffer.from(
        `${introspectionConfig.clientId}:${introspectionConfig.clientSecret}`
      ).toString('base64')}`
    },
    body: `token=${encodeURIComponent(token)}`
  });

  if (!response.ok) {
    throw new InvalidSubjectTokenError('Token introspection failed');
  }

  const result = await response.json() as { active: boolean; [key: string]: unknown };
  
  if (!result.active) {
    throw new InvalidSubjectTokenError('Token is not active');
  }

  return result as JWTPayload;
}

/**
 * Apply audience and scope mapping
 */
function applyAudienceScopeMapping(
  payload: JWTPayload,
  request: TokenExchangeRequest,
  mappings: AudienceScopeMapping[]
): { audience: string; scope?: string; additionalClaims: Record<string, unknown> } {
  const sourceAudience = payload.aud as string;
  let targetAudience = request.audience || sourceAudience;
  let mappedScope: string | undefined = request.scope || (payload.scope as string);
  let additionalClaims: Record<string, unknown> = {};

  for (const mapping of mappings) {
    const matches = typeof mapping.sourceAudience === 'string' 
      ? sourceAudience === mapping.sourceAudience
      : mapping.sourceAudience.test(sourceAudience);

    if (matches) {
      targetAudience = mapping.targetAudience;
      
      // Apply scope mapping
      if (mapping.scopeMapping && payload.scope) {
        const payloadScope = payload.scope as string;
        const sourceScopes = typeof payloadScope === 'string' 
          ? payloadScope.split(' ') 
          : [payloadScope];
        
        const mappedScopes: string[] = [];
        for (const sourceScope of sourceScopes) {
          const mapped = mapping.scopeMapping[sourceScope as string];
          if (mapped) {
            if (Array.isArray(mapped)) {
              mappedScopes.push(...mapped);
            } else {
              mappedScopes.push(mapped);
            }
          } else {
            mappedScopes.push(sourceScope); // Keep original if no mapping
          }
        }
        mappedScope = mappedScopes.join(' ');
      }

      // Add additional claims
      if (mapping.additionalClaims) {
        additionalClaims = { ...additionalClaims, ...mapping.additionalClaims };
      }

      break; // Use first matching mapping
    }
  }

  return {
    audience: targetAudience,
    scope: mappedScope,
    additionalClaims
  };
}

/**
 * Provider-aware token validation
 */
export async function validateSubjectToken(
  token: string,
  tokenType: string,
  options: CustomTokenExchangeOptions
): Promise<{ payload: JWTPayload; providerName?: string }> {
  // Validate token type support
  validateTokenTypeSupport(tokenType, options.supportedTokenTypes);

  // First decode without verification to get issuer
  const unverifiedPayload = jwt.decode(token) as JWTPayload;
  if (!unverifiedPayload || !unverifiedPayload.iss) {
    throw new InvalidSubjectTokenError('Invalid token format or missing issuer');
  }

  const providers = [...DEFAULT_PROVIDERS, ...(options.providers || [])];
  const provider = detectProvider(unverifiedPayload.iss, providers);

  // Use introspection for external tokens if configured
  if (options.tokenValidation?.useIntrospection && options.introspection) {
    const payload = await validateTokenViaIntrospection(token, options.introspection);
    return { payload, providerName: provider?.name };
  }

  // Provider-specific validation
  if (provider?.customValidator) {
    const payload = await provider.customValidator(token);
    return { payload, providerName: provider.name };
  }

  // Standard JWT validation
  return new Promise((resolve, reject) => {
    // Prioritize explicitly configured algorithms over provider defaults
    const algorithms = options.algorithms || provider?.algorithms || ['HS256', 'RS256'];
    const secret = options.keyPair?.publicKey || options.secret;
    
    if (!secret) {
      reject(new InvalidSubjectTokenError('No secret or public key provided for token validation'));
      return;
    }

    const jwtOptions: jwt.VerifyOptions = {
      issuer: provider ? unverifiedPayload.iss : options.issuer,
      audience: options.audience,
      algorithms: algorithms as jwt.Algorithm[],
      clockTolerance: options.tokenValidation?.clockTolerance || 60,
      ignoreExpiration: options.tokenValidation?.ignoreExpiration || false,
      ignoreNotBefore: options.tokenValidation?.ignoreNotBefore || false,
      maxAge: options.tokenValidation?.maxAge
    };

    jwt.verify(token, secret, jwtOptions, (err, decoded) => {
      if (err) {
        reject(new InvalidSubjectTokenError(`Token validation failed: ${err.message}`));
        return;
      }

      const payload = decoded as JWTPayload;

      // Custom validation if provided
      if (options.tokenValidation?.customValidation) {
        if (!options.tokenValidation.customValidation(payload)) {
          reject(new InvalidSubjectTokenError('Custom token validation failed'));
          return;
        }
      }

      resolve({ payload, providerName: provider?.name });
    });
  });
}

/**
 * Validate actor token for delegation scenarios
 */
async function validateActorToken(
  actorToken: string,
  actorTokenType: string,
  options: CustomTokenExchangeOptions
): Promise<ActorTokenInfo> {
  const { payload } = await validateSubjectToken(actorToken, actorTokenType, options);
  return {
    payload,
    tokenType: actorTokenType
  };
}

/**
 * Enhanced default token exchange handler with provider awareness and mapping
 */
export const defaultTokenExchangeHandler: TokenExchangeHandler = (
  subjectPayload: JWTPayload,
  request: TokenExchangeRequest,
  originalRequest: Request & { tokenExchangeOptions?: CustomTokenExchangeOptions },
  actorInfo?: ActorTokenInfo
): TokenExchangeResponse => {
  const options = originalRequest.tokenExchangeOptions;
  
  // Apply audience and scope mapping
  const { audience, scope, additionalClaims } = applyAudienceScopeMapping(
    subjectPayload,
    request,
    options?.audienceScopeMapping || []
  );

  // Create new payload with mapped claims
  const expiresIn = options?.responseOptions?.expiresIn || 3600;
  const newPayload: JWTPayload = {
    ...subjectPayload,
    aud: audience,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn,
    ...additionalClaims
  };

  // Add actor information for delegation
  if (actorInfo) {
    newPayload.act = {
      sub: actorInfo.payload.sub,
      iss: actorInfo.payload.iss
    };
  }

  // Sign with appropriate key
  const signingKey = options?.keyPair?.privateKey || options?.secret || 'your-secret-key';
  const algorithm = options?.keyPair?.algorithm || 'HS256';
  
  const signOptions: jwt.SignOptions = {
    algorithm: algorithm as jwt.Algorithm,
    ...(options?.keyPair?.kid && { keyid: options.keyPair.kid })
  };

  const accessToken = jwt.sign(newPayload, signingKey, signOptions);

  return {
    access_token: accessToken,
    issued_token_type: request.requested_token_type || TOKEN_TYPES.ACCESS_TOKEN,
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: scope
  };
};

/**
 * Validates the token exchange request according to RFC 8693
 */
export function validateTokenExchangeRequest(body: Record<string, unknown>): TokenExchangeRequest {
  if (!body.grant_type || body.grant_type !== TOKEN_EXCHANGE_GRANT_TYPE) {
    throw new TokenExchangeError('Invalid or missing grant_type', 'invalid_request');
  }

  if (!body.subject_token) {
    throw new TokenExchangeError('Missing required parameter: subject_token', 'invalid_request');
  }

  if (!body.subject_token_type) {
    throw new TokenExchangeError('Missing required parameter: subject_token_type', 'invalid_request');
  }

  return {
    grant_type: body.grant_type as string,
    subject_token: body.subject_token as string,
    subject_token_type: body.subject_token_type as string,
    audience: body.audience as string | undefined,
    scope: body.scope as string | undefined,
    requested_token_type: body.requested_token_type as string | undefined,
    resource: body.resource as string | undefined,
    actor_token: body.actor_token as string | undefined,
    actor_token_type: body.actor_token_type as string | undefined
  };
}

/**
 * Creates the token exchange response with proper RFC 8693 formatting
 */
export function createTokenExchangeResponse(
  tokenResponse: TokenExchangeResponse,
  options?: ResponseOptions,
  providerName?: string
): TokenExchangeResponse {
  const response: TokenExchangeResponse = {
    access_token: tokenResponse.access_token,
    issued_token_type: tokenResponse.issued_token_type,
    token_type: tokenResponse.token_type || 'Bearer',
  };

  if (tokenResponse.expires_in || options?.expiresIn) {
    response.expires_in = options?.expiresIn || tokenResponse.expires_in;
  }

  if (tokenResponse.scope) {
    response.scope = tokenResponse.scope;
  }

  if (tokenResponse.refresh_token) {
    response.refresh_token = tokenResponse.refresh_token;
  }

  // Add general additional fields
  if (options?.additionalFields) {
    Object.assign(response, options.additionalFields);
  }

  // Add provider-specific additional fields
  if (providerName && options?.providerAdditionalFields?.[providerName]) {
    Object.assign(response, options.providerAdditionalFields[providerName]);
  }

  return response;
}

/**
 * Creates an Express middleware for handling RFC 8693 token exchange requests
 * 
 * @param options Configuration options for token exchange
 * @returns Express middleware handler
 * 
 * @example
 * ```typescript
 * const app = express();
 * 
 * app.use('/oauth/token', customTokenExchange({
 *   issuer: 'https://your-auth0-domain.auth0.com/',
 *   audience: 'your-api-identifier',
 *   keyPair: {
 *     privateKey: fs.readFileSync('private-key.pem'),
 *     publicKey: fs.readFileSync('public-key.pem'),
 *     algorithm: 'RS256'
 *   },
 *   supportedTokenTypes: [TOKEN_TYPES.JWT, TOKEN_TYPES.ID_TOKEN, TOKEN_TYPES.SAML2],
 *   enableActorTokens: true,
 *   audienceScopeMapping: [{
 *     sourceAudience: 'external-api',
 *     targetAudience: 'internal-api',
 *     scopeMapping: { 'read': ['internal:read', 'internal:list'] }
 *   }]
 * }));
 * ```
 */
export function customTokenExchange(options: CustomTokenExchangeOptions): Handler {
  const exchangeHandler = options.exchangeHandler || defaultTokenExchangeHandler;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Only handle POST requests to token endpoints
      if (req.method !== 'POST') {
        return next();
      }

      // Store options in request for access by handler
      const extReq = req as Request & { 
        tokenExchangeOptions?: CustomTokenExchangeOptions;
        body: Record<string, unknown>;
      };
      extReq.tokenExchangeOptions = options;

      // Validate the token exchange request
      const exchangeRequest = validateTokenExchangeRequest(extReq.body);

      // Validate and decode the subject token with provider detection
      const { payload: subjectPayload, providerName } = await validateSubjectToken(
        exchangeRequest.subject_token,
        exchangeRequest.subject_token_type,
        options
      );

      // Validate actor token if present and enabled
      let actorInfo: ActorTokenInfo | undefined;
      if (options.enableActorTokens && exchangeRequest.actor_token && exchangeRequest.actor_token_type) {
        try {
          actorInfo = await validateActorToken(
            exchangeRequest.actor_token,
            exchangeRequest.actor_token_type,
            options
          );
        } catch (error) {
          throw new TokenExchangeError('Invalid actor token', 'invalid_grant');
        }
      }

      // Store token exchange data in request for potential use by other middleware
      const reqWithExchange = req as Request & {
        tokenExchange?: {
          subjectPayload: JWTPayload;
          exchangeRequest: TokenExchangeRequest;
          actorInfo?: ActorTokenInfo;
          providerName?: string;
        };
      };
      reqWithExchange.tokenExchange = {
        subjectPayload,
        exchangeRequest,
        actorInfo,
        providerName
      };

      // Execute the token exchange handler
      const tokenResponse = await exchangeHandler(
        subjectPayload,
        exchangeRequest,
        req,
        actorInfo
      );

      // Create the standardized response with provider-specific enhancements
      const response = createTokenExchangeResponse(
        tokenResponse,
        options.responseOptions,
        providerName
      );

      // Set appropriate headers according to RFC 6749
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (res as any).set({
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache'
      });

      // Send the token exchange response
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (res as any).json(response);

    } catch (error) {
      // Enhanced error handling according to RFC 6749 and RFC 8693
      let errorCode = 'invalid_request';
      let statusCode = 400;
      let errorMessage = 'Invalid token exchange request';

      if (error instanceof TokenExchangeError) {
        errorCode = error.error;
        errorMessage = error.message;
      } else if (error instanceof InvalidSubjectTokenError) {
        errorCode = 'invalid_grant';
        errorMessage = error.message;
      } else if (error instanceof UnsupportedTokenTypeError) {
        errorCode = 'unsupported_token_type';
        errorMessage = error.message;
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }

      // Set appropriate status code based on error type
      if (errorCode === 'invalid_grant' || errorCode === 'invalid_token') {
        statusCode = 401;
      } else if (errorCode === 'unsupported_token_type') {
        statusCode = 400;
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (res as any).status(statusCode).json({
        error: errorCode,
        error_description: errorMessage
      });
    }
  };
}

/**
 * Utility function to create a basic Auth0-compatible token exchange middleware
 * 
 * @param issuer Auth0 domain (e.g., 'https://your-domain.auth0.com/')
 * @param audience API identifier
 * @param secret JWT secret or certificate
 * @returns Express middleware for token exchange
 */
export function auth0TokenExchange(
  issuer: string,
  audience: string,
  secret: string
): Handler {
  return customTokenExchange({
    issuer,
    audience,
    secret,
    algorithms: ['RS256'],
    supportedTokenTypes: [TOKEN_TYPES.ACCESS_TOKEN, TOKEN_TYPES.ID_TOKEN, TOKEN_TYPES.JWT],
    enableActorTokens: true,
    tokenValidation: {
      clockTolerance: 60, // 1 minute tolerance
      ignoreExpiration: false,
      ignoreNotBefore: false
    },
    responseOptions: {
      issuedTokenType: TOKEN_TYPES.ACCESS_TOKEN,
      expiresIn: 3600 // 1 hour
    }
  });
}

/**
 * Error classes for token exchange with proper RFC mapping
 */
export class TokenExchangeError extends Error {
  constructor(
    message: string,
    public readonly error: string = 'invalid_request'
  ) {
    super(message);
    this.name = 'TokenExchangeError';
  }
}

export class InvalidSubjectTokenError extends TokenExchangeError {
  constructor(message: string) {
    super(message, 'invalid_grant');
    this.name = 'InvalidSubjectTokenError';
  }
}

export class UnsupportedTokenTypeError extends TokenExchangeError {
  constructor(tokenType: string) {
    super(`Unsupported token type: ${tokenType}`, 'unsupported_token_type');
    this.name = 'UnsupportedTokenTypeError';
  }
}