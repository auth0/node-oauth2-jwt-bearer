/**
 * Get a Bearer Token from a request per https://tools.ietf.org/html/rfc6750#section-2
 */
import { InvalidRequestError } from './errors';

const METHODS_WITHOUT_BODY = ['GET', 'HEAD', 'DELETE'];

type QueryLike = Record<string, unknown> & { access_token?: string };
type BodyLike = QueryLike;
type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  'content-type'?: string;
};

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

const getTokenFromQuery = (method: string, query?: QueryLike) => {
  const accessToken = query?.access_token;
  if (
    typeof accessToken === 'string' &&
    METHODS_WITHOUT_BODY.includes(method)
  ) {
    return accessToken;
  }
};

const getFromBody = (method: string, headers: HeadersLike, body?: BodyLike) => {
  const accessToken = body?.access_token;
  if (
    typeof accessToken === 'string' &&
    !METHODS_WITHOUT_BODY.includes(method) &&
    headers['content-type'] === 'application/x-www-form-urlencoded'
  ) {
    return accessToken;
  }
};

/**
 * Get a Bearer Token from a request.
 *
 * @param method The request method.
 * @param headers An object containing the request headers, usually `req.headers`.
 * @param query An object containing the request query parameters, usually `req.query`.
 * @param body An object containing the request payload, usually `req.body` or `req.payload`.
 */
export default function getToken(
  method: string,
  headers: HeadersLike,
  query?: QueryLike,
  body?: BodyLike
): string {
  const fromHeader = getTokenFromHeader(headers);
  const fromQuery = getTokenFromQuery(method, query);
  const fromBody = getFromBody(method, headers, body);

  if (!fromQuery && !fromHeader && !fromBody) {
    throw new InvalidRequestError('Bearer token is missing');
  }

  if (+!!fromQuery + +!!fromBody + +!!fromHeader > 1) {
    throw new InvalidRequestError(
      'More than one method used for authentication'
    );
  }

  return (fromQuery || fromBody || fromHeader) as string;
}
