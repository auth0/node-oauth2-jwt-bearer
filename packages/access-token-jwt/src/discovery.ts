import { URL } from 'url';
import fetch from './fetch';
import { strict as assert } from 'assert';
import { JwtVerifierOptions } from './jwt-verifier';
import { LRUCache } from './lru-cache';

const OIDC_DISCOVERY = '/.well-known/openid-configuration';
const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';

export interface IssuerMetadata {
  issuer: string;
  jwks_uri: string;
  id_token_signing_alg_values_supported?: string[];
  [key: string]: unknown;
}

const assertIssuer = (data: IssuerMetadata) =>
  assert(data.issuer, `'issuer' not found in authorization server metadata`);

export type DiscoverOptions = Required<
  Pick<JwtVerifierOptions, 'timeoutDuration' | 'cacheMaxAge'>
> &
  Pick<JwtVerifierOptions, 'agent' | 'cache'>;

const discover = async (
  uri: string,
  opts: Pick<DiscoverOptions, 'agent' | 'timeoutDuration'>
): Promise<IssuerMetadata> => {
  const { agent, timeoutDuration } = opts;
  const url = new URL(uri);

  if (url.pathname.includes('/.well-known/')) {
    const data = await fetch<IssuerMetadata>(url, { agent, timeoutDuration });
    assertIssuer(data);
    return data;
  }

  const pathnames = [];
  if (url.pathname.endsWith('/')) {
    pathnames.push(`${url.pathname}${OIDC_DISCOVERY.substring(1)}`);
  } else {
    pathnames.push(`${url.pathname}${OIDC_DISCOVERY}`);
  }
  if (url.pathname === '/') {
    pathnames.push(`${OAUTH2_DISCOVERY}`);
  } else {
    pathnames.push(`${OAUTH2_DISCOVERY}${url.pathname}`);
  }

  for (const pathname of pathnames) {
    try {
      const wellKnownUri = new URL(pathname, url);
      const data = await fetch<IssuerMetadata>(wellKnownUri, {
        agent,
        timeoutDuration,
      });
      assertIssuer(data);
      return data;
    } catch (err) {
      // noop
    }
  }

  throw new Error('Failed to fetch authorization server metadata');
};

export default (opts: Omit<DiscoverOptions, 'issuerBaseURL'>) => {
  // Create LRU cache for discovery metadata
  // Use cache.discovery options if provided, otherwise fall back to cacheMaxAge (deprecated)
  const cacheOptions = {
    maxEntries: opts.cache?.discovery?.maxEntries ?? 100,
    // Note: cacheMaxAge is always defined (has default value), so final fallback never reached
    ttl: /* istanbul ignore next */ opts.cache?.discovery?.ttl ?? opts.cacheMaxAge ?? 600000,
  };

  const discoveryCache = new LRUCache<Promise<IssuerMetadata>>(cacheOptions);

  return (issuerBaseURL: string): Promise<IssuerMetadata> => {
    // Check cache first
    const cached = discoveryCache.get(issuerBaseURL);
    if (cached) {
      return cached;
    }

    // Perform discovery and cache the promise
    const promise = discover(issuerBaseURL, opts).catch((e) => {
      // Remove failed request from cache so it can be retried
      discoveryCache.delete(issuerBaseURL);
      throw e;
    });

    discoveryCache.set(issuerBaseURL, promise);
    return promise;
  };
};
