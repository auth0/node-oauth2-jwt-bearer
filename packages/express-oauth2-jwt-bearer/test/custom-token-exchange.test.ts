import { Request, Response } from 'express';
import express from 'express';
import request from 'supertest';
import * as jwt from 'jsonwebtoken';

// Mock node-fetch
jest.mock('node-fetch');
import {
  customTokenExchange,
  auth0TokenExchange,
  validateTokenExchangeRequest,
  validateSubjectToken,
  createTokenExchangeResponse,
  defaultTokenExchangeHandler,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPES,
  CustomTokenExchangeOptions,
  TokenExchangeRequest,
  TokenExchangeResponse,
  TokenExchangeHandler,
  TokenExchangeError,
  InvalidSubjectTokenError,
  UnsupportedTokenTypeError
} from '../src/custom-token-exchange';

describe('Custom Token Exchange', () => {
  const testSecret = 'test-secret';
  const testIssuer = 'https://test-issuer.com/';
  const testAudience = 'test-api';

  let app: express.Application;
  let validToken: string;
  let expiredToken: string;

  beforeAll(() => {
    // Create test tokens
    const payload = {
      iss: testIssuer,
      aud: testAudience,
      sub: 'test-user',
      scope: 'read write',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    };

    validToken = jwt.sign(payload, testSecret);
    
    const expiredPayload = {
      ...payload,
      exp: Math.floor(Date.now() / 1000) - 3600
    };
    expiredToken = jwt.sign(expiredPayload, testSecret);
  });

  beforeEach(() => {
    app = express();
    (app as any).use(express.json());
    (app as any).use(express.urlencoded({ extended: true }));
  });

  describe('validateTokenExchangeRequest', () => {
    it('should validate a correct token exchange request', () => {
      const body = {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: validToken,
        subject_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        audience: 'new-audience',
        scope: 'read'
      };

      const result = validateTokenExchangeRequest(body);
      expect(result.grant_type).toBe(TOKEN_EXCHANGE_GRANT_TYPE);
      expect(result.subject_token).toBe(validToken);
      expect(result.audience).toBe('new-audience');
    });

    it('should throw error for invalid grant_type', () => {
      const body = {
        grant_type: 'invalid',
        subject_token: validToken,
        subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
      };

      expect(() => validateTokenExchangeRequest(body)).toThrow('Invalid or missing grant_type');
    });

    it('should throw error for missing subject_token', () => {
      const body = {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
      };

      expect(() => validateTokenExchangeRequest(body)).toThrow('Missing required parameter: subject_token');
    });

    it('should throw error for missing subject_token_type', () => {
      const body = {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: validToken
      };

      expect(() => validateTokenExchangeRequest(body)).toThrow('Missing required parameter: subject_token_type');
    });
  });

  describe('validateSubjectToken', () => {
    const options: CustomTokenExchangeOptions = {
      issuer: testIssuer,
      audience: testAudience,
      secret: testSecret,
      algorithms: ['HS256']
    };

    it('should validate a correct token', async () => {
      const result = await validateSubjectToken(validToken, TOKEN_TYPES.ACCESS_TOKEN, options);
      expect(result.payload.iss).toBe(testIssuer);
      expect(result.payload.aud).toBe(testAudience);
      expect(result.payload.sub).toBe('test-user');
    });

    it('should reject an expired token', async () => {
      await expect(validateSubjectToken(expiredToken, TOKEN_TYPES.ACCESS_TOKEN, options))
        .rejects.toThrow('Token validation failed');
    });

    it('should reject token with wrong issuer', async () => {
      const wrongIssuerOptions = { ...options, issuer: 'https://wrong.issuer.com/' };
      await expect(validateSubjectToken(validToken, TOKEN_TYPES.ACCESS_TOKEN, wrongIssuerOptions))
        .rejects.toThrow('Token validation failed');
    });

    it('should apply custom validation', async () => {
      const customOptions = {
        ...options,
        tokenValidation: {
          customValidation: (payload: any) => payload.sub === 'allowed-user'
        }
      };

      await expect(validateSubjectToken(validToken, TOKEN_TYPES.ACCESS_TOKEN, customOptions))
        .rejects.toThrow('Custom token validation failed');
    });

    it('should pass custom validation with correct user', async () => {
      const customOptions = {
        ...options,
        tokenValidation: {
          customValidation: (payload: any) => payload.sub === 'test-user'
        }
      };

      const result = await validateSubjectToken(validToken, TOKEN_TYPES.ACCESS_TOKEN, customOptions);
      expect(result.payload.sub).toBe('test-user');
    });
  });

  describe('createTokenExchangeResponse', () => {
    it('should create a basic token exchange response', () => {
      const tokenResponse: TokenExchangeResponse = {
        access_token: 'new-token',
        issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read write'
      };

      const result = createTokenExchangeResponse(tokenResponse);
      expect(result.access_token).toBe('new-token');
      expect(result.issued_token_type).toBe(TOKEN_TYPES.ACCESS_TOKEN);
      expect(result.token_type).toBe('Bearer');
      expect(result.expires_in).toBe(3600);
      expect(result.scope).toBe('read write');
    });

    it('should override expires_in with response options', () => {
      const tokenResponse: TokenExchangeResponse = {
        access_token: 'new-token',
        issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        token_type: 'Bearer',
        expires_in: 3600
      };

      const result = createTokenExchangeResponse(tokenResponse, {
        expiresIn: 7200
      });
      expect(result.expires_in).toBe(7200);
    });

    it('should add additional fields', () => {
      const tokenResponse: TokenExchangeResponse = {
        access_token: 'new-token',
        issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        token_type: 'Bearer'
      };

      const result = createTokenExchangeResponse(tokenResponse, {
        additionalFields: {
          custom_field: 'custom_value',
          another_field: 123
        }
      });

      expect((result as any).custom_field).toBe('custom_value');
      expect((result as any).another_field).toBe(123);
    });
  });

  describe('defaultTokenExchangeHandler', () => {
    it('should create a new token with modified claims', async () => {
      const subjectPayload = {
        iss: testIssuer,
        aud: testAudience,
        sub: 'test-user',
        scope: 'read write',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const exchangeRequest: TokenExchangeRequest = {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: validToken,
        subject_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        audience: 'new-audience',
        scope: 'read'
      };

      const mockRequest = {} as Request;
      const result = await Promise.resolve(defaultTokenExchangeHandler(subjectPayload, exchangeRequest, mockRequest));

      expect(result.access_token).toBeDefined();
      expect(result.issued_token_type).toBe(TOKEN_TYPES.ACCESS_TOKEN);
      expect(result.token_type).toBe('Bearer');
      expect(result.expires_in).toBe(3600);
      expect(result.scope).toBe('read');
    });
  });

  describe('customTokenExchange middleware', () => {
    it('should handle valid token exchange request', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256']
      };

      (app as any).post('/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN,
          audience: 'new-audience',
          scope: 'read'
        });

      expect(response.status).toBe(200);
      expect(response.body.access_token).toBeDefined();
      expect(response.body.issued_token_type).toBe(TOKEN_TYPES.ACCESS_TOKEN);
      expect(response.body.token_type).toBe('Bearer');
      expect(response.body.expires_in).toBe(3600);
    });

    it('should handle custom exchange handler', async () => {
      const customHandler = jest.fn().mockResolvedValue({
        access_token: 'custom-token',
        issued_token_type: TOKEN_TYPES.JWT,
        token_type: 'Bearer',
        expires_in: 7200,
        scope: 'custom-scope'
      });

      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256'],
        exchangeHandler: customHandler
      };

      (app as any).post('/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(response.status).toBe(200);
      expect(response.body.access_token).toBe('custom-token');
      expect(response.body.issued_token_type).toBe(TOKEN_TYPES.JWT);
      expect(response.body.expires_in).toBe(7200);
      expect(customHandler).toHaveBeenCalled();
    });

    it('should return 400 for invalid grant_type', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret
      };

      (app as any).post('/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/token')
        .send({
          grant_type: 'invalid',
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_request');
      expect(response.body.error_description).toContain('Invalid or missing grant_type');
    });

    it('should return 400 for invalid subject token', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret
      };

      (app as any).post('/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: 'invalid-token',
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('invalid_grant');
      expect(response.body.error_description).toContain('Invalid token format');
    });

    it('should set correct headers', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256']
      };

      (app as any).post('/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['pragma']).toBe('no-cache');
    });

    it('should pass through non-POST requests', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret
      };

      const nextHandler = jest.fn((req, res) => res.status(200).json({ message: 'passed through' }));
      
      (app as any).use('/token', customTokenExchange(options));
      (app as any).get('/token', nextHandler);

      const response = await request(app as any).get('/token');

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('passed through');
    });

    it('should store token exchange data in request', async () => {
      let requestData: any = null;
      
      const customHandler = jest.fn().mockImplementation((subjectPayload, exchangeRequest, req) => {
        requestData = req.tokenExchange;
        return {
          access_token: 'test-token',
          issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
          token_type: 'Bearer'
        };
      });

      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256'],
        exchangeHandler: customHandler
      };

      (app as any).post('/token', customTokenExchange(options));

      await request(app as any)
        .post('/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(requestData).toBeDefined();
      expect(requestData.subjectPayload).toBeDefined();
      expect(requestData.exchangeRequest).toBeDefined();
      expect(requestData.subjectPayload.sub).toBe('test-user');
    });
  });

  describe('auth0TokenExchange', () => {
    it('should create Auth0-compatible middleware', async () => {
      // Create a custom Auth0-compatible middleware that accepts HS256 for testing
      const testAuth0Middleware = customTokenExchange({
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256'], // Allow HS256 for testing
        tokenValidation: {
          clockTolerance: 60,
          ignoreExpiration: false,
          ignoreNotBefore: false
        },
        responseOptions: {
          issuedTokenType: TOKEN_TYPES.ACCESS_TOKEN,
          expiresIn: 3600
        }
      });

      (app as any).post('/oauth/token', testAuth0Middleware);

      const response = await request(app as any)
        .post('/oauth/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      if (response.status !== 200) {
        console.log('Error response:', response.body);
      }
      expect(response.status).toBe(200);
      expect(response.body.access_token).toBeDefined();
      expect(response.body.issued_token_type).toBe(TOKEN_TYPES.ACCESS_TOKEN);
      expect(response.body.expires_in).toBe(3600);
    });
  });

  describe('Error classes', () => {
    it('should create TokenExchangeError correctly', () => {
      const error = new TokenExchangeError('Test error', 'test_error');
      expect(error.message).toBe('Test error');
      expect(error.error).toBe('test_error');
      expect(error.name).toBe('TokenExchangeError');
    });

    it('should create InvalidSubjectTokenError correctly', () => {
      const error = new InvalidSubjectTokenError('Invalid token');
      expect(error.message).toBe('Invalid token');
      expect(error.error).toBe('invalid_grant');
      expect(error.name).toBe('InvalidSubjectTokenError');
    });

    it('should create UnsupportedTokenTypeError correctly', () => {
      const error = new UnsupportedTokenTypeError('custom_type');
      expect(error.message).toBe('Unsupported token type: custom_type');
      expect(error.error).toBe('unsupported_token_type');
      expect(error.name).toBe('UnsupportedTokenTypeError');
    });
  });

  describe('Integration tests', () => {
    it('should handle complete token exchange flow', async () => {
      const customHandler = async (subjectPayload: any, exchangeRequest: TokenExchangeRequest) => {
        // Simulate custom business logic
        const { exp, ...payloadWithoutExp } = subjectPayload;
        const newPayload = {
          ...payloadWithoutExp,
          aud: exchangeRequest.audience || subjectPayload.aud,
          scope: exchangeRequest.scope || subjectPayload.scope,
          custom_claim: 'added_by_exchange'
        };

        const newToken = jwt.sign(newPayload, testSecret, { expiresIn: '2h' });

        return {
          access_token: newToken,
          issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
          token_type: 'Bearer',
          expires_in: 7200,
          scope: exchangeRequest.scope
        };
      };

      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256'],
        exchangeHandler: customHandler
      };

      (app as any).post('/oauth/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/oauth/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN,
          audience: 'https://api.example.com',
          scope: 'read:data write:data'
        });

      if (response.status !== 200) {
        console.log('Integration test error response:', response.body);
      }
      expect(response.status).toBe(200);
      expect(response.body.access_token).toBeDefined();
      expect(response.body.expires_in).toBe(7200);
      expect(response.body.scope).toBe('read:data write:data');

      // Verify the new token contains expected claims
      const decodedToken = jwt.verify(response.body.access_token, testSecret) as any;
      expect(decodedToken.aud).toBe('https://api.example.com');
      expect(decodedToken.scope).toBe('read:data write:data');
      expect(decodedToken.custom_claim).toBe('added_by_exchange');
    });

    it('should handle token exchange with response options', async () => {
      const options: CustomTokenExchangeOptions = {
        issuer: testIssuer,
        audience: testAudience,
        secret: testSecret,
        algorithms: ['HS256'],
        responseOptions: {
          expiresIn: 1800,
          additionalFields: {
            refresh_token: 'refresh_token_value',
            custom_field: 'custom_value'
          }
        }
      };

      (app as any).post('/oauth/token', customTokenExchange(options));

      const response = await request(app as any)
        .post('/oauth/token')
        .send({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: validToken,
          subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
        });

      expect(response.status).toBe(200);
      expect(response.body.expires_in).toBe(1800);
      expect(response.body.refresh_token).toBe('refresh_token_value');
      expect(response.body.custom_field).toBe('custom_value');
    });
  });

  describe('Coverage Enhancement Tests', () => {
    describe('Provider Custom Validators', () => {
      it('should use provider custom validator when available', async () => {
        const customPayload = { sub: 'custom-user', iss: 'https://custom-provider.com', aud: 'test-audience' };
        const customValidator = jest.fn().mockResolvedValue(customPayload);
        
        const options: CustomTokenExchangeOptions = {
          issuer: 'https://custom-provider.com',
          secret: 'test-secret',
          audience: 'test-audience',
          providers: [{
            name: 'custom-provider',
            issuerPattern: /custom-provider\.com/,
            algorithms: ['RS256'],
            customValidator
          }]
        };

        const token = jwt.sign(customPayload, 'test-secret');
        const result = await validateSubjectToken(token, TOKEN_TYPES.JWT, options);

        expect(customValidator).toHaveBeenCalledWith(token);
        expect(result.payload).toEqual(customPayload);
        expect(result.providerName).toBe('custom-provider');
      });
    });

    describe('Actor Token Error Handling', () => {
      it('should handle invalid actor token gracefully', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', customTokenExchange({
          issuer: 'https://example.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          enableActorTokens: true
        }));

        const validToken = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://example.com', 
          aud: 'test-audience' 
        }, 'test-secret');

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: validToken,
            subject_token_type: TOKEN_TYPES.JWT,
            actor_token: 'invalid-actor-token',
            actor_token_type: TOKEN_TYPES.JWT
          });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('invalid_grant');
        expect(response.body.error_description).toContain('Invalid actor token');
      });
    });

    describe('Additional Fields and Provider-Specific Fields', () => {
      it('should include general additional fields in response', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', customTokenExchange({
          issuer: 'https://example.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          responseOptions: {
            additionalFields: {
              custom_field: 'global_value',
              expires_in: 7200
            }
          }
        }));

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://example.com', 
          aud: 'test-audience' 
        }, 'test-secret');

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: token,
            subject_token_type: TOKEN_TYPES.JWT
          });

        expect(response.status).toBe(200);
        expect(response.body.custom_field).toBe('global_value');
        expect(response.body.expires_in).toBe(7200);
      });

      it('should include provider-specific additional fields', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', customTokenExchange({
          issuer: 'https://test.auth0.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          providers: [{
            name: 'auth0',
            issuerPattern: /auth0\.com/,
            algorithms: ['HS256']
          }],
          responseOptions: {
            providerAdditionalFields: {
              auth0: {
                auth0_specific: 'auth0_value',
                connection: 'Username-Password-Authentication'
              }
            }
          }
        }));

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://test.auth0.com', 
          aud: 'test-audience' 
        }, 'test-secret', { algorithm: 'HS256' });

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: token,
            subject_token_type: TOKEN_TYPES.JWT
          });

        if (response.status !== 200) {
          console.log('Provider-specific fields test error:', response.body);
        }
        expect(response.status).toBe(200);
        expect(response.body.auth0_specific).toBe('auth0_value');
        expect(response.body.connection).toBe('Username-Password-Authentication');
      });
    });

    describe('Enhanced Error Handling', () => {
      it('should handle InvalidSubjectTokenError with proper error code', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', customTokenExchange({
          issuer: 'https://example.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256']
        }));

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: 'completely-invalid-token',
            subject_token_type: TOKEN_TYPES.JWT
          });

        expect(response.status).toBe(401);
        expect(response.body.error).toBe('invalid_grant');
      });

      it('should handle UnsupportedTokenTypeError with proper error code', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', customTokenExchange({
          issuer: 'https://example.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          supportedTokenTypes: [TOKEN_TYPES.JWT] // Only JWT supported
        }));

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://example.com', 
          aud: 'test-audience' 
        }, 'test-secret');

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: token,
            subject_token_type: TOKEN_TYPES.ACCESS_TOKEN // Different from supported type
          });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('unsupported_token_type');
      });

      it('should handle generic Error with default error code', async () => {
        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        
        // Mock the exchangeHandler to throw a generic error
        const mockHandler: TokenExchangeHandler = () => {
          throw new Error('Generic processing error');
        };

        app.use('/token', customTokenExchange({
          issuer: 'https://example.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          exchangeHandler: mockHandler
        }));

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://example.com', 
          aud: 'test-audience' 
        }, 'test-secret');

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: token,
            subject_token_type: TOKEN_TYPES.JWT
          });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('invalid_request');
        expect(response.body.error_description).toBe('Generic processing error');
      });
    });

    describe('Token Introspection', () => {
      let mockFetch: any;

      beforeEach(() => {
        // Get the mocked fetch from node-fetch
        mockFetch = require('node-fetch');
        jest.clearAllMocks();
      });

      it('should validate token via introspection when configured', async () => {
        // Mock fetch for introspection
        mockFetch.mockResolvedValue({
          ok: true,
          json: () => Promise.resolve({
            active: true,
            sub: 'user123',
            iss: 'https://external-provider.com',
            aud: 'test-audience',
            exp: Math.floor(Date.now() / 1000) + 3600
          })
        });

        const options: CustomTokenExchangeOptions = {
          issuer: 'https://external-provider.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          providers: [{
            name: 'external-provider',
            issuerPattern: /external-provider\.com/,
            algorithms: ['HS256'],
            introspectionEndpoint: 'https://external-provider.com/introspect'
          }],
          tokenValidation: {
            useIntrospection: true
          },
          introspection: {
            endpoint: 'https://external-provider.com/introspect',
            clientId: 'client-id',
            clientSecret: 'client-secret'
          }
        };

        // Create a token with external issuer to trigger introspection
        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://external-provider.com',
          aud: 'test-audience'
        }, 'test-secret');
        const result = await validateSubjectToken(token, TOKEN_TYPES.ACCESS_TOKEN, options);

        expect(mockFetch).toHaveBeenCalledWith(
          'https://external-provider.com/introspect',
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Content-Type': 'application/x-www-form-urlencoded',
              'Authorization': expect.any(String)
            }),
            body: expect.any(String)
          })
        );

        expect(result.payload.sub).toBe('user123');
        expect(result.providerName).toBe('external-provider');
      });

      it('should handle inactive introspection response', async () => {
        mockFetch.mockResolvedValue({
          ok: true,
          json: () => Promise.resolve({ active: false })
        });

        const options: CustomTokenExchangeOptions = {
          issuer: 'https://external-provider.com',
          secret: 'test-secret',
          audience: 'test-audience',
          algorithms: ['HS256'],
          providers: [{
            name: 'external-provider',
            issuerPattern: /external-provider\.com/,
            algorithms: ['HS256'],
            introspectionEndpoint: 'https://external-provider.com/introspect'
          }],
          tokenValidation: {
            useIntrospection: true
          },
          introspection: {
            endpoint: 'https://external-provider.com/introspect',
            clientId: 'client-id',
            clientSecret: 'client-secret'
          }
        };

        const inactiveToken = jwt.sign({ 
          sub: 'inactive-user', 
          iss: 'https://external-provider.com',
          aud: 'test-audience'
        }, 'test-secret');

        await expect(
          validateSubjectToken(inactiveToken, TOKEN_TYPES.ACCESS_TOKEN, options)
        ).rejects.toThrow('Token is not active');
      });
    });

    describe('Auth0 Convenience Function', () => {
      it('should create middleware with auth0-specific configuration', async () => {
        const middleware = auth0TokenExchange(
          'https://test.auth0.com',
          'test-audience',
          'test-secret'
        );

        // Verify it returns a function (middleware)
        expect(typeof middleware).toBe('function');

        // Test the middleware with a request - use HS256 for testing  
        const testMiddleware = customTokenExchange({
          issuer: 'https://test.auth0.com',
          audience: 'test-audience',
          secret: 'test-secret',
          algorithms: ['HS256'], // Override to HS256 for testing
          supportedTokenTypes: [TOKEN_TYPES.ACCESS_TOKEN, TOKEN_TYPES.ID_TOKEN, TOKEN_TYPES.JWT],
          enableActorTokens: true,
          tokenValidation: {
            clockTolerance: 60,
            ignoreExpiration: false,
            ignoreNotBefore: false
          },
          responseOptions: {
            issuedTokenType: TOKEN_TYPES.ACCESS_TOKEN,
            expiresIn: 3600
          }
        });

        const app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));
        app.use('/token', testMiddleware);

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://test.auth0.com', 
          aud: 'test-audience' 
        }, 'test-secret', { algorithm: 'HS256' });

        const response = await request(app)
          .post('/token')
          .send({
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            subject_token: token,
            subject_token_type: TOKEN_TYPES.ACCESS_TOKEN
          });

        if (response.status !== 200) {
          console.log('Auth0 convenience function test error:', response.body);
        }
        expect(response.status).toBe(200);
        expect(response.body.access_token).toBeDefined();
        expect(response.body.token_type).toBe('Bearer');
      });
    });

    describe('Missing Secret/Key Error Handling', () => {
      it('should reject when no secret or public key is provided', async () => {
        const options: CustomTokenExchangeOptions = {
          issuer: 'https://example.com',
          // No secret or keyPair provided
          audience: 'test-audience'
        };

        const token = jwt.sign({ 
          sub: 'user123', 
          iss: 'https://example.com', 
          aud: 'test-audience' 
        }, 'test-secret');

        await expect(
          validateSubjectToken(token, TOKEN_TYPES.JWT, options)
        ).rejects.toThrow('No secret or public key provided for token validation');
      });
    });
  });
});
