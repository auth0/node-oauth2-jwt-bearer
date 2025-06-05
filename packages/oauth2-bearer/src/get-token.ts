/**
 * Get a Bearer Token from a request per https://tools.ietf.org/html/rfc6750#section-2
 */
import { InvalidRequestError, UnauthorizedError } from './errors';

type QueryLike = Record<string, unknown> & { access_token?: string };
type BodyLike = QueryLike;
type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  'content-type'?: string;
};

/**
 * Enum for the different locations where a token can be found
 */
export enum TokenLocation {
  HEADER = 'header',
  QUERY = 'query',
  BODY = 'body'
}

/**
 * Options for the getToken function
 */
export interface GetTokenOptions {
  /**
   * Whether to check for the token in the Authorization header
   * @default true
   */
  checkHeader?: boolean;

  /**
   * Whether to check for the token in the query parameters
   * @default true
   */
  checkQuery?: boolean;

  /**
   * Whether to check for the token in the request body
   * @default true
   */
  checkBody?: boolean;
}

const TOKEN_RE = /^Bearer (.+)$/i;

const getTokenFromHeader = (headers: HeadersLike) => {
  if (typeof headers.authorization !== 'string') {
    return;
  }
  const match = headers.authorization.match(TOKEN_RE);
  if (!match) {
    return;
  }
  return match[1];
};

const getTokenFromQuery = (query?: QueryLike) => {
  const accessToken = query?.access_token;
  if (typeof accessToken === 'string') {
    return accessToken;
  }
};

const getFromBody = (body?: BodyLike, urlEncoded?: boolean) => {
  const accessToken = body?.access_token;
  if (typeof accessToken === 'string' && urlEncoded) {
    return accessToken;
  }
};

/**
 * Get a Bearer Token from a request.
 *
 * @param headers An object containing the request headers, usually `req.headers`.
 * @param query An object containing the request query parameters, usually `req.query`.
 * @param body An object containing the request payload, usually `req.body` or `req.payload`.
 * @param urlEncoded true if the request's Content-Type is `application/x-www-form-urlencoded`.
 * @param options Options to specify which locations to check for tokens.
 */
export default function getToken(
  headers: HeadersLike,
  query?: QueryLike,
  body?: BodyLike,
  urlEncoded?: boolean,
  options?: GetTokenOptions
): string {
  const opts: GetTokenOptions = {
    checkHeader: true,
    checkQuery: true,
    checkBody: true,
    ...(options || {})
  };
  
  const fromHeader = opts.checkHeader ? getTokenFromHeader(headers) : undefined;
  const fromQuery = opts.checkQuery ? getTokenFromQuery(query) : undefined;
  const fromBody = opts.checkBody ? getFromBody(body, urlEncoded) : undefined;

  if (!fromQuery && !fromHeader && !fromBody) {
    throw new UnauthorizedError();
  }

  if (+!!fromQuery + +!!fromBody + +!!fromHeader > 1) {
    throw new InvalidRequestError(
      'More than one method used for authentication'
    );
  }

  return (fromQuery || fromBody || fromHeader) as string;
}
