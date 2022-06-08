import {
  InvalidTokenError,
  InsufficientScopeError,
  UnauthorizedError,
} from 'oauth2-bearer';
import type { JWTPayload } from 'jose';

export type JSONPrimitive = string | number | boolean | null;

type ClaimChecker = (payload?: JWTPayload) => void;

const checkJSONPrimitive = (value: JSONPrimitive): void => {
  if (
    typeof value !== 'string' &&
    typeof value !== 'number' &&
    typeof value !== 'boolean' &&
    value !== null
  ) {
    throw new TypeError("'expected' must be a string, number, boolean or null");
  }
};

const isClaimIncluded = (
  claim: string,
  expected: JSONPrimitive[]
): ((payload: JWTPayload) => boolean) => (payload) => {
  if (!(claim in payload)) {
    throw new InvalidTokenError(`Missing '${claim}' claim`);
  }

  let actual = payload[claim];
  if (typeof actual === 'string') {
    actual = actual.split(' ');
  } else if (!Array.isArray(actual)) {
    return false;
  }

  actual = new Set(actual as JSONPrimitive[]);

  return expected.every(Set.prototype.has.bind(actual));
};

export type RequiredScopes<R = ClaimChecker> = (scopes: string | string[]) => R;

export const requiredScopes: RequiredScopes = (scopes) => {
  if (typeof scopes === 'string') {
    scopes = scopes.split(' ');
  } else if (!Array.isArray(scopes)) {
    throw new TypeError("'scopes' must be a string or array of strings");
  }
  const fn = (scope: string) => isClaimIncluded(scope, scopes as string[]);
  return claimCheck((payload) => {
    let scopeField: string
    if ('scp' in payload) {
      scopeField = 'scp';
    } else if ('scopes' in payload) {
      scopeField = 'scopes';
    } else if ('scope' in payload) {
      scopeField = 'scope';
    } else {
      throw new InsufficientScopeError(
          scopes as string[],
          "Missing 'scope' claim"
      );
    }

    if (!fn(scopeField)(payload)) {
      throw new InsufficientScopeError(scopes as string[]);
    }
    return true;
  });
};

export type ClaimIncludes<R = ClaimChecker> = (
  claim: string,
  ...expected: JSONPrimitive[]
) => R;

export const claimIncludes: ClaimIncludes = (claim, ...expected) => {
  if (typeof claim !== 'string') {
    throw new TypeError("'claim' must be a string");
  }
  expected.forEach(checkJSONPrimitive);

  return claimCheck(
    isClaimIncluded(claim, expected),
    `Unexpected '${claim}' value`
  );
};

export type ClaimEquals<R = ClaimChecker> = (
  claim: string,
  expected: JSONPrimitive
) => R;

export const claimEquals: ClaimEquals = (claim, expected) => {
  if (typeof claim !== 'string') {
    throw new TypeError("'claim' must be a string");
  }
  checkJSONPrimitive(expected);

  return claimCheck((payload) => {
    if (!(claim in payload)) {
      throw new InvalidTokenError(`Missing '${claim}' claim`);
    }
    return payload[claim] === expected;
  }, `Unexpected '${claim}' value`);
};

export type ClaimCheck<R = ClaimChecker> = (
  fn: (payload: JWTPayload) => boolean,
  errMsg?: string
) => R;

export const claimCheck: ClaimCheck = (fn, errMsg) => {
  if (typeof fn !== 'function') {
    throw new TypeError("'claimCheck' expects a function");
  }

  return (payload?: JWTPayload) => {
    if (!payload) {
      throw new UnauthorizedError();
    }
    if (!fn(payload)) {
      throw new InvalidTokenError(errMsg);
    }
  };
};
