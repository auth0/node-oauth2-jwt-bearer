import { Handler, NextFunction, Request, Response } from 'express';
import {
  jwtVerifier,
  WithDiscovery,
  WithoutDiscovery,
  claimCheck as _claimCheck,
  ClaimCheck,
  claimEquals as _claimEquals,
  ClaimEquals,
  claimIncludes as _claimIncludes,
  ClaimIncludes,
  requiredScopes as _requiredScopes,
  RequiredScopes,
} from 'access-token-jwt';
import { getToken } from 'oauth2-bearer';

declare global {
  namespace Express {
    interface Request {
      auth?: { payload: JWTPayload };
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

const toHandler = (fn: (payload?: JWTPayload) => void): Handler => (
  req,
  res,
  next
) => {
  try {
    fn(req.auth?.payload);
    next();
  } catch (e) {
    next(e);
  }
};

export const claimCheck: ClaimCheck<Handler> = (...args) =>
  toHandler(_claimCheck(...args));

export const claimEquals: ClaimEquals<Handler> = (...args) =>
  toHandler(_claimEquals(...args));

export const claimIncludes: ClaimIncludes<Handler> = (...args) =>
  toHandler(_claimIncludes(...args));

export const requiredScopes: RequiredScopes<Handler> = (...args) =>
  toHandler(_requiredScopes(...args));
