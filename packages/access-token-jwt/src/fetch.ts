import { URL } from 'url';
import { get as getHttp } from 'http';
import { get as getHttps } from 'https';
import { once } from 'events';
import type { ClientRequest, IncomingMessage } from 'http';
import { FetchError, JsonParseError } from './errors';

const decoder = new TextDecoder();

const concat = (...buffers: Uint8Array[]): Uint8Array => {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach((buffer) => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
};

const protocols: {
  [protocol: string]: (...args: Parameters<typeof getHttps>) => ClientRequest;
} = {
  'https:': getHttps,
  'http:': getHttp,
};

const fetch = async <TResponse>(url: URL): Promise<TResponse> => {
  const req = protocols[url.protocol](url.href, {});

  const [response] = <[IncomingMessage]>await once(req, 'response');

  if (response.statusCode !== 200) {
    throw new FetchError(url.href, response.statusCode, response.statusMessage);
  }

  const parts = [];
  for await (const part of response) {
    parts.push(part);
  }

  try {
    return JSON.parse(decoder.decode(concat(...parts)));
  } catch (err) {
    throw new JsonParseError(url.href);
  }
};

export default fetch;
