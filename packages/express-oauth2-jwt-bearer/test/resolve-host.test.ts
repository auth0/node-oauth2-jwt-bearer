import type { Request } from 'express';
import { resolveHost } from '../src/resolve-host';

type TrustProxyFn = (addr: string | null | undefined, index: number) => boolean;

export function mkReq({
  host,
  xfh,
  remoteAddress = '127.0.0.1',
  trustFn,
  noGet = false,
}: {
  host?: string | string[];
  xfh?: string | string[];
  remoteAddress?: string | null;
  trustFn?: TrustProxyFn | unknown;
  noGet?: boolean;
}): Request {
  const headers: Record<string, string | string[] | undefined> = {};
  if (host !== undefined) headers['host'] = host;
  if (xfh !== undefined) headers['x-forwarded-host'] = xfh;

  const getHeader: {
    (name: 'set-cookie'): string[] | undefined;
    (name: string): string | undefined;
  } = ((name: string) => {
    const key = name.toLowerCase();
    const value = headers[key];
    if (key === 'set-cookie') {
      return Array.isArray(value) ? value : undefined;
    }
    return Array.isArray(value) ? undefined : value;
  }) as any;

  const reqLike: Partial<Request> = {
    socket: { remoteAddress } as any,
    app: {
      get: (key: string) => (key === 'trust proxy fn' ? trustFn : undefined),
    } as any,
  };

  if (!noGet) {
    (reqLike as any).get = getHeader as Request['get'];
  }

  return reqLike as Request;
}

describe('resolveHost (Express 4/5 compatible)', () => {
  test('returns Host when X-Forwarded-Host is missing', () => {
    const req = mkReq({ host: 'internal:3000', trustFn: () => true });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('returns Host when X-Forwarded-Host is present but proxy is NOT trusted', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      trustFn: () => false,
    });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('returns X-Forwarded-Host (single value) when proxy IS trusted', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('api.example.com');
  });

  test('uses only the first value of a multi-value X-Forwarded-Host when trusted', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com, cdn.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('api.example.com');
  });

  test('trims trailing whitespace before the comma on first XFH value', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com   , another.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('api.example.com');
  });

  test('returns Host when X-Forwarded-Host is an empty string', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: '',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('returns undefined when both Host and X-Forwarded-Host are missing', () => {
    const req = mkReq({ trustFn: () => true });
    expect(resolveHost(req)).toBeUndefined();
  });

  test('returns X-Forwarded-Host when Host is missing but proxy is trusted', () => {
    const req = mkReq({
      xfh: 'public.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('public.example.com');
  });

  test('returns Host when req.app is missing entirely', () => {
    const req = mkReq({ host: 'internal:3000', xfh: 'api.example.com' }) as any;
    delete req.app; // simulate no app on the request
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('returns Host when trust proxy fn is NOT provided (treated as untrusted)', () => {
    const req = mkReq({ host: 'internal:3000', xfh: 'api.example.com', trustFn: undefined });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('respects remoteAddress in trust fn (trusted)', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      remoteAddress: '10.0.0.2',
      trustFn: (addr: string | null | undefined, i: number) =>
        addr === '10.0.0.2' && i === 0,
    });
    expect(resolveHost(req)).toBe('api.example.com');
  });

  test('respects remoteAddress in trust fn (untrusted)', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      remoteAddress: '10.0.0.2',
      trustFn: (addr: string | null | undefined, _i: number) =>
        addr === '127.0.0.1',
    });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('handles IPv6 Host header when XFH missing', () => {
    const req = mkReq({
      host: '[::1]:3000',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('[::1]:3000');
  });

  test('handles IPv6 X-Forwarded-Host when trusted', () => {
    const req = mkReq({
      host: '[::1]:3000',
      xfh: '[2001:db8::1]',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('[2001:db8::1]');
  });

  test('handles multi-value IPv6 X-Forwarded-Host when trusted and trims', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: '[2001:db8::1]  , other.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('[2001:db8::1]');
  });

  test('Host present, XFH present but undefined trust fn uses Host', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      trustFn: undefined,
    });
    expect(resolveHost(req)).toBe('internal:3000');
  });

  test('Host missing, XFH present, undefined trust fn returns undefined', () => {
    const req = mkReq({
      xfh: 'api.example.com',
      trustFn: undefined,
    });
    expect(resolveHost(req)).toBeUndefined();
  });

  test('Host missing, XFH multi-value, trusted returns first XFH', () => {
    const req = mkReq({
      xfh: 'a.example.com, b.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('a.example.com');
  });

  test('returns undefined when req.get is missing entirely', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'api.example.com',
      trustFn: () => true,
      noGet: true,
    });
    expect(resolveHost(req)).toBeUndefined();
  });

  test('returns empty string when Host is an empty string and XFH is missing', () => {
    const req = mkReq({
      host: '',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('');
  });

  test('returns XFH when req.socket is missing', () => {
    const req = mkReq({ host: 'internal:3000', xfh: 'api.example.com', trustFn: () => true }) as any;
    delete req.socket; // simulate no socket on the request
    expect(resolveHost(req)).toBe('api.example.com');
  });

  test('returns exact XFH when trusted and no comma present (no trimming path)', () => {
    const req = mkReq({
      xfh: 'edge.example.com   ',
      host: 'internal:3000',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('edge.example.com   ');
  });

  test('returns undefined when first XFH value is whitespace only after trimming', () => {
    const req = mkReq({
      xfh: '   , b.example.com',
      host: 'internal:3000',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBeUndefined();
  });

  test('does not throw if remoteAddress is undefined and proxy is trusted unconditionally', () => {
    const req = mkReq({
      host: 'internal:3000',
      xfh: 'pub.example.com',
      remoteAddress: null,
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('pub.example.com');
  });
});
