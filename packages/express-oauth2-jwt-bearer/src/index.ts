import { Handler, NextFunction, Request, Response } from 'express';
import { jwtVerifier, WithDiscovery, WithoutDiscovery } from 'access-token-jwt';
import { getToken } from 'oauth2-bearer';

declare global {
  namespace Express {
    interface Request {
      auth: { payload: JWTPayload };
    }
  }
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

export interface Auth {
  (opts: WithDiscovery): Handler;
  (opts: WithoutDiscovery): Handler;
}

export const auth: Auth = (opts: any): Handler => {
  const verifyJwt = jwtVerifier(opts);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const jwt = getToken(
        req.headers,
        req.query,
        req.body,
        !!req.is('urlencoded')
      );
      req.auth = await verifyJwt(jwt);
      next();
    } catch (e) {
      next(e);
    }
  };
};
