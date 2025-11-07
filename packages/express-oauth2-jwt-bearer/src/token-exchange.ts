import { URL } from 'url';
import { request } from 'https';
import { request as httpRequest } from 'http';
import type { Agent as HttpAgent } from 'http';
import type { Agent as HttpsAgent } from 'https';

export interface TokenExchangeOptions {
  /**
   * The authorization server's token endpoint URL for token exchange
   */
  tokenEndpoint: string;

  /**
   * The client ID to use for token exchange
   */
  clientId: string;

  /**
   * The client secret to use for token exchange (optional for public clients)
   */
  clientSecret?: string;

  /**
   * The target audience for the exchanged token
   */
  targetAudience?: string;

  /**
   * The requested token type (default: "urn:ietf:params:oauth:token-type:access_token")
   */
  requestedTokenType?: string;

  /**
   * Additional scopes to request for the exchanged token
   */
  scope?: string;

  /**
   * HTTP agent for proxy support
   */
  agent?: HttpAgent | HttpsAgent;

  /**
   * Request timeout in milliseconds
   */
  timeoutDuration?: number;
}

export interface TokenExchangeResult {
  /**
   * The exchanged access token
   */
  access_token: string;

  /**
   * The token type (usually "Bearer")
   */
  token_type: string;

  /**
   * Token expiration time in seconds
   */
  expires_in?: number;

  /**
   * Refresh token if provided
   */
  refresh_token?: string;

  /**
   * Scope of the exchanged token
   */
  scope?: string;
}

/**
 * Exchange an access token for another token using OAuth 2.0 Token Exchange (RFC 8693)
 * 
 * @param subjectToken - The token to be exchanged
 * @param options - Token exchange configuration options
 * @returns Promise resolving to the exchanged token
 */
export async function exchangeToken(
  subjectToken: string,
  options: TokenExchangeOptions
): Promise<TokenExchangeResult> {
  const {
    tokenEndpoint,
    clientId,
    clientSecret,
    targetAudience,
    requestedTokenType = 'urn:ietf:params:oauth:token-type:access_token',
    scope,
    agent,
    timeoutDuration = 5000,
  } = options;

  // Prepare the token exchange request body
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
  params.append('subject_token', subjectToken);
  params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token');
  params.append('client_id', clientId);
  params.append('requested_token_type', requestedTokenType);

  if (targetAudience) {
    params.append('audience', targetAudience);
  }

  if (scope) {
    params.append('scope', scope);
  }

  // Prepare headers
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  };

  // Use basic auth if client secret is provided
  if (clientSecret) {
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const body = params.toString();
  headers['Content-Length'] = Buffer.byteLength(body).toString();

  return new Promise((resolve, reject) => {
    const url = new URL(tokenEndpoint);
    const requestOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: 'POST',
      headers,
      agent,
      timeout: timeoutDuration,
    };

    const requestFn = url.protocol === 'https:' ? request : httpRequest;
    const req = requestFn(requestOptions, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`Token exchange failed with status ${res.statusCode}: ${data}`));
          return;
        }

        try {
          const result = JSON.parse(data) as TokenExchangeResult;
          resolve(result);
        } catch (parseError) {
          const errorMessage = parseError instanceof Error ? parseError.message : String(parseError);
          reject(new Error(`Failed to parse token exchange response: ${errorMessage}`));
        }
      });
    });

    req.on('error', (error: Error) => {
      reject(new Error(`Token exchange request failed: ${error.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Token exchange request timed out'));
    });

    req.write(body);
    req.end();
  });
}
