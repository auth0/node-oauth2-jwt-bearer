import type { Request } from 'express';

// Resolve host in a way that's compatible with both Express 4 and 5.
export function resolveHost(req: Request): string | undefined {
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
    return get ? get('Host') : undefined;
  }

  // If XFH had multiple values, only keep the first one
  const i = host.indexOf(',');
  if (i !== -1) {
    host = host.substring(0, i).trimEnd(); // trim spaces after the first value
  }

  // At this point host is either the first XFH value or a single host
  return host || undefined;
}
