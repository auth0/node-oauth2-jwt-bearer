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

  test('Host missing, XFH multi-value, trusted returns first XFH', () => {
    const req = mkReq({
      xfh: 'a.example.com, b.example.com',
      trustFn: () => true,
    });
    expect(resolveHost(req)).toBe('a.example.com');
  });

  test('returns XFH when req.socket is missing', () => {
    const req = mkReq({ host: 'internal:3000', xfh: 'api.example.com', trustFn: () => true }) as any;
    delete req.socket; // simulate no socket on the request
    expect(resolveHost(req)).toBe('api.example.com');
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

  describe('Unit: Host Validation (new throwing contract)', () => {
    // UT-1: valid plain host
    test('UT-1: valid plain host returns string', () => {
      const req = mkReq({ host: 'resource.com', trustFn: () => true });
      expect(resolveHost(req)).toBe('resource.com');
    });

    // UT-2: host with port
    test('UT-2: host with port returns string', () => {
      const req = mkReq({ host: 'resource.com:8443', trustFn: () => true });
      expect(resolveHost(req)).toBe('resource.com:8443');
    });

    // UT-3: IPv6 literal host
    test('UT-3: IPv6 literal host returns string', () => {
      const req = mkReq({ host: '[::1]:3000', trustFn: () => true });
      expect(resolveHost(req)).toBe('[::1]:3000');
    });

    // UT-4: injected path+query in Host throws
    test('UT-4: injected path+query in Host throws InvalidRequestError', () => {
      const req = mkReq({ host: 'resource.com/intendedPath?', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-5: injected fragment in Host throws
    test('UT-5: injected fragment in Host throws InvalidRequestError', () => {
      const req = mkReq({ host: 'resource.com/intendedPath#', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-6: double-slash in Host throws
    test('UT-6: double-slash in Host throws InvalidRequestError', () => {
      const req = mkReq({ host: 'resource.com//evil', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-7: scheme-in-Host throws
    test('UT-7: scheme-in-Host throws InvalidRequestError', () => {
      const req = mkReq({ host: 'https://resource.com', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-8: trusted XFH carrying injection throws
    test('UT-8: trusted XFH carrying injection throws InvalidRequestError', () => {
      const req = mkReq({ host: 'internal:3000', xfh: 'resource.com/x?', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-9: trusted multi-value XFH keeps and validates first value
    test('UT-9: trusted multi-value XFH keeps and validates first value', () => {
      const req = mkReq({ host: 'internal:3000', xfh: 'a.com, b.com', trustFn: () => true });
      expect(resolveHost(req)).toBe('a.com');
    });

    // UT-EMPTY: trusted XFH leading-comma yields empty -> throws
    test('UT-EMPTY: trusted XFH leading-comma yields empty -> throws', () => {
      const req = mkReq({ xfh: ', b.com', host: 'internal:3000', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // UT-MSG: single generic reject message across reasons
    test('UT-MSG: single generic reject message (structural char reject)', () => {
      const req = mkReq({ host: 'resource.com/evil?', trustFn: () => true });
      let thrown: any;
      try {
        resolveHost(req);
        fail('Should throw');
      } catch (e) {
        thrown = e;
      }
      expect(thrown.message).toBe('Invalid Host header');
    });

    test('UT-MSG: single generic reject message (missing-host reject)', () => {
      const req = mkReq({ trustFn: () => true }); // no host, no xfh
      let thrown: any;
      try {
        resolveHost(req);
        fail('Should throw');
      } catch (e) {
        thrown = e;
      }
      expect(thrown.message).toBe('Invalid Host header');
    });

    // EC-1: trailing-dot host
    test('EC-1: trailing-dot host accepted and returned', () => {
      const req = mkReq({ host: 'resource.com.', trustFn: () => true });
      expect(resolveHost(req)).toBe('resource.com.');
    });

    // EC-2: userinfo in host rejected
    test('EC-2: userinfo in host rejected', () => {
      const req = mkReq({ host: 'user:pass@resource.com', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // EC-3: port-only overflow / non-numeric port
    test('EC-3: non-numeric port rejected', () => {
      const req = mkReq({ host: 'resource.com:notaport', trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });
  });

  describe('Migration: Old contract -> New throwing contract', () => {
    // MIG-1: "returns undefined when both Host and XFH missing" -> now throws
    test('MIG-1: throws when both Host and X-Forwarded-Host are missing', () => {
      const req = mkReq({ trustFn: () => true });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // MIG-2: "Host missing, XFH present, undefined trust fn returns undefined" -> now throws
    test('MIG-2: throws when Host missing, XFH present, undefined trust fn', () => {
      const req = mkReq({
        xfh: 'api.example.com',
        trustFn: undefined,
      });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // MIG-3: "returns undefined when req.get is missing entirely" -> now throws
    test('MIG-3: throws when req.get is missing entirely', () => {
      const req = mkReq({
        host: 'internal:3000',
        xfh: 'api.example.com',
        trustFn: () => true,
        noGet: true,
      });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // MIG-4: "returns empty string when Host is empty and XFH missing" -> now throws
    test('MIG-4: throws when Host is empty string and XFH missing', () => {
      const req = mkReq({
        host: '',
        trustFn: () => true,
      });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // MIG-5: "returns exact XFH when trusted and no comma (no trimming)" with trailing spaces -> now throws
    test('MIG-5: throws when trusted XFH has trailing spaces that fail HOST_RE', () => {
      const req = mkReq({
        xfh: 'edge.example.com   ',
        host: 'internal:3000',
        trustFn: () => true,
      });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });

    // MIG-6: "returns undefined when first XFH value is whitespace only after trimming" -> now throws
    test('MIG-6: throws when first XFH value is whitespace only after trimming', () => {
      const req = mkReq({
        xfh: '   , b.example.com',
        host: 'internal:3000',
        trustFn: () => true,
      });
      expect(() => resolveHost(req)).toThrow(
        expect.objectContaining({
          message: 'Invalid Host header',
        })
      );
    });
  });
});
