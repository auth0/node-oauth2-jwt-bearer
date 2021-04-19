import { URL } from 'url';
import fetch from './fetch';
import { strict as assert } from 'assert';

const OIDC_DISCOVERY = '/.well-known/openid-configuration';
const OAUTH2_DISCOVERY = '/.well-known/oauth-authorization-server';

export interface IssuerMetadata {
  issuer: string;
  jwks_uri: string;
  [key: string]: unknown;
}

const assertIssuer = (data: IssuerMetadata) =>
  assert(data.issuer, `"issuer" not found in authorization server metadata`);

const discover = async (uri: string): Promise<IssuerMetadata> => {
  const url = new URL(uri);

  if (url.pathname.includes('/.well-known/')) {
    const data = await fetch<IssuerMetadata>(url);
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

  const errors = [];
  for (const pathname of pathnames) {
    try {
      const wellKnownUri = new URL(pathname, url);
      const data = await fetch<IssuerMetadata>(wellKnownUri);
      assertIssuer(data);
      return data;
    } catch (err) {
      errors.push(err);
    }
  }

  throw new Error(errors.map(({ message }) => message).join('\n'));
};

export default discover;
