import { URL } from 'url';
import fetch from './fetch';
import { strict as assert } from 'assert';
import { JwtVerifierOptions } from './jwt-verifier';

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
  Pick<JwtVerifierOptions, 'issuerBaseURL' | 'timeoutDuration' | 'cacheMaxAge'>
> &
  Pick<JwtVerifierOptions, 'agent'>;

const discover = async ({
  issuerBaseURL: uri,
  agent,
  timeoutDuration,
}: DiscoverOptions): Promise<IssuerMetadata> => {
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

export default (opts: DiscoverOptions) => {
  let discovery: Promise<IssuerMetadata> | undefined;
  let timestamp = 0;

  return () => {
    const now = Date.now();

    if (!discovery || now > timestamp + opts.cacheMaxAge) {
      timestamp = now;
      discovery = discover(opts).catch((e) => {
        discovery = undefined;
        throw e;
      });
    }
    return discovery;
  };
};
