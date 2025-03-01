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

const TOKEN_RE = /^Bearer (.+)$/i;

const getTokenFromHeader = (tokenLocation: string, headers: HeadersLike) => {
  if (typeof headers[tokenLocation] !== 'string') {
    return;
  }
  const match = (headers[tokenLocation] as string).match(TOKEN_RE);
  if (!match) {
    return;
  }
  return match[1];
};

const getTokenFromQuery = (tokenLocation: string, query?: QueryLike) => {
  const accessToken = query?.[tokenLocation];
  if (typeof accessToken === 'string') {
    return accessToken;
  }
};

const getFromBody = (tokenLocation: string, body?: BodyLike, urlEncoded?: boolean) => {
  const accessToken = body?.[tokenLocation];
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
 * @param tokenLocation The name of header or body / query parameter to extract the JWT from.
 */
export default function getToken(
  headers: HeadersLike,
  query?: QueryLike,
  body?: BodyLike,
  urlEncoded?: boolean,
  tokenLocation?: string
): string {
  const headerLocation = tokenLocation ?? "authorization";
  const queryOrBodyLocation = tokenLocation ?? "access_token";

  const fromHeader = getTokenFromHeader(headerLocation, headers);
  const fromQuery = getTokenFromQuery(queryOrBodyLocation, query);
  const fromBody = getFromBody(queryOrBodyLocation, body, urlEncoded);

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
