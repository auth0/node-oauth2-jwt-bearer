import type { Request } from 'express';
import { InvalidRequestError } from 'access-token-jwt';

// Hostname grammar: a registered name or bracketed IPv6 literal, with an
// optional :port. Mirrors the host check used during DPoP htu normalization.
const HOST_RE = /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;

// Validate the raw, untrusted host value BEFORE it is concatenated into a URL.
// Rejecting structural characters here prevents Host-header injection from
// being laundered into the query/fragment by later URL parsing.
function isValidHost(host: string | undefined): host is string {
  return (
    typeof host === 'string' &&
    host.length > 0 &&
    !host.includes('://') &&
    !host.includes('/') &&
    !host.includes('?') &&
    !host.includes('#') &&
    HOST_RE.test(host)
  );
}

// Resolve host in a way that's compatible with both Express 4 and 5.
// Throws InvalidRequestError if the resolved host is missing or malformed.
export function resolveHost(req: Request): string {
  // Extract the trust proxy function from the app settings
  const trust = req.app?.get?.('trust proxy fn');

  // Make sure we have a usable req.get method before calling it
  const get = typeof req.get === 'function' ? req.get.bind(req) : undefined;

  // First, try the X-Forwarded-Host header (if present)
  let host = get ? get('X-Forwarded-Host') : undefined;

  // If XFH is missing, or the proxy isn't trusted, just fall back to Host
  if (
    !host ||
    !(typeof trust === 'function' && trust(req.socket?.remoteAddress, 0))
  ) {
    host = get ? get('Host') : undefined;
  } else {
    // If XFH had multiple values, only keep the first one
    const i = host.indexOf(',');
    if (i !== -1) {
      host = host.substring(0, i).trimEnd(); // trim spaces after the first value
    }
  }

  // Validate the untrusted host at the single return point, covering both the
  // X-Forwarded-Host and Host paths. A single generic message is used for every
  // reason so we don't signal which check failed.
  if (!isValidHost(host)) {
    throw new InvalidRequestError('Invalid Host header');
  }

  return host;
}
