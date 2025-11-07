import nock from 'nock';
import {
  exchangeToken,
  TokenExchangeOptions,
  TokenExchangeResult,
} from '../src/token-exchange';

describe('Token Exchange', () => {
  const mockTokenEndpoint = 'https://auth.example.com/oauth/token';
  const mockClientId = 'test-client-id';
  const mockClientSecret = 'test-client-secret';
  const mockSubjectToken = 'subject-access-token';
  const mockTargetAudience = 'https://api.example.com';

  const mockTokenResponse: TokenExchangeResult = {
    access_token: 'exchanged-access-token',
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'read:data',
  };

  beforeEach(() => {
    nock.cleanAll();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  describe('exchangeToken function', () => {
    it('should successfully exchange a token', async () => {
      const expectedBody = [
        'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange',
        'subject_token=subject-access-token',
        'subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token',
        'client_id=test-client-id',
        'requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token',
        'audience=https%3A%2F%2Fapi.example.com',
      ].join('&');

      nock('https://auth.example.com')
        .post('/oauth/token', expectedBody)
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
      };

      const result = await exchangeToken(mockSubjectToken, options);

      expect(result).toEqual(mockTokenResponse);
    });

    it('should include client secret in basic auth when provided', async () => {
      nock('https://auth.example.com')
        .post('/oauth/token')
        .matchHeader('authorization', 'Basic dGVzdC1jbGllbnQtaWQ6dGVzdC1jbGllbnQtc2VjcmV0')
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        clientSecret: mockClientSecret,
        targetAudience: mockTargetAudience,
      };

      const result = await exchangeToken(mockSubjectToken, options);
      expect(result).toEqual(mockTokenResponse);
    });

    it('should include scope when provided', async () => {
      const expectedBodyWithScope = [
        'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange',
        'subject_token=subject-access-token',
        'subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token',
        'client_id=test-client-id',
        'requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token',
        'audience=https%3A%2F%2Fapi.example.com',
        'scope=read%3Adata%20write%3Adata',
      ].join('&');

      nock('https://auth.example.com')
        .post('/oauth/token', expectedBodyWithScope)
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
        scope: 'read:data write:data',
      };

      const result = await exchangeToken(mockSubjectToken, options);
      expect(result).toEqual(mockTokenResponse);
    });

    it('should use custom requested token type when provided', async () => {
      const expectedBodyWithCustomType = [
        'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange',
        'subject_token=subject-access-token',
        'subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token',
        'client_id=test-client-id',
        'requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token',
        'audience=https%3A%2F%2Fapi.example.com',
      ].join('&');

      nock('https://auth.example.com')
        .post('/oauth/token', expectedBodyWithCustomType)
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
        requestedTokenType: 'urn:ietf:params:oauth:token-type:refresh_token',
      };

      const result = await exchangeToken(mockSubjectToken, options);
      expect(result).toEqual(mockTokenResponse);
    });

    it('should handle HTTP endpoints', async () => {
      nock('http://auth.example.com')
        .post('/oauth/token')
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: 'http://auth.example.com/oauth/token',
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
      };

      const result = await exchangeToken(mockSubjectToken, options);
      expect(result).toEqual(mockTokenResponse);
    });

    it('should handle token exchange errors', async () => {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The provided authorization grant is invalid',
      };

      nock('https://auth.example.com')
        .post('/oauth/token')
        .reply(400, errorResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
      };

      await expect(exchangeToken(mockSubjectToken, options))
        .rejects
        .toThrow('Token exchange failed with status 400');
    });

    it('should handle network errors', async () => {
      nock('https://auth.example.com')
        .post('/oauth/token')
        .replyWithError('Network error');

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
      };

      await expect(exchangeToken(mockSubjectToken, options))
        .rejects
        .toThrow('Token exchange request failed: Network error');
    });

    it('should handle invalid JSON responses', async () => {
      nock('https://auth.example.com')
        .post('/oauth/token')
        .reply(200, 'invalid json');

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
      };

      await expect(exchangeToken(mockSubjectToken, options))
        .rejects
        .toThrow('Failed to parse token exchange response');
    });

    it('should handle timeout', async () => {
      nock('https://auth.example.com')
        .post('/oauth/token')
        .delay(6000)
        .reply(200, mockTokenResponse);

      const options: TokenExchangeOptions = {
        tokenEndpoint: mockTokenEndpoint,
        clientId: mockClientId,
        targetAudience: mockTargetAudience,
        timeoutDuration: 1000,
      };

      await expect(exchangeToken(mockSubjectToken, options))
        .rejects
        .toThrow('Token exchange request timed out');
    });
  });
});
