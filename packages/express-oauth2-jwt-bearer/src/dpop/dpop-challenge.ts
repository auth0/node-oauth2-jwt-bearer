import type { Request } from 'express';

export interface AuthError extends Error {
  code?: string;
  status?: number;
  statusCode?: number;
  headers?: Record<string, string>;
}

interface DPoPConfig {
  enabled?: boolean;
  required?: boolean;
}

export function getAuthChallenges(
  req: Request,
  err: unknown,
  dpop: DPoPConfig = {},
  supportedAlgs: string[] = ['ES256']
): string[] {
  const authHeader = req.headers['authorization']?.toLowerCase();
  const hasBearer = authHeader?.startsWith('bearer ');
  const hasDpop = authHeader?.startsWith('dpop ');

  const e = err as AuthError;
  const errorCode = e?.code || 'invalid_token';
  const description = e?.message || 'Unauthorized';
  const safeDescription = description.replace(/"/g, "'");

  const challenges: string[] = [];
  const isDPoPEnabled = dpop?.enabled ?? true;
  const isDPoPRequired = dpop?.required ?? false;

  /*
    DPoP challenge use-cases:
    If no authentication information has been included with the request, then the challenges SHOULD NOT include an error code or other error information.
    If the mechanism used to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to deliver error information.
    Otherwise, both Bearer and DPoP challenges MAY be used to deliver error information.
    If DPoP is enabled in allowed mode, then both Bearer and DPoP challenges MAY be used to deliver error information.
    If DPoP is enabled in required mode, then only DPoP challenges SHOULD be used to deliver error information.
  */

  if (isDPoPEnabled) {
    if (!hasBearer && !hasDpop) {
      if (isDPoPRequired) {
        challenges.push(
          `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${supportedAlgs.join(
            ' '
          )}"`
        );
      } else {
        challenges.push(`Bearer realm="api"`);
        challenges.push(`DPoP algs="${supportedAlgs.join(' ')}"`);
      }
    } else if (hasBearer && !hasDpop) {
      if (isDPoPRequired) {
        challenges.push(
          `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${supportedAlgs.join(
            ' '
          )}"`
        );
      } else {
        challenges.push(
          `Bearer realm="api", error="${errorCode}", error_description="${safeDescription}"`
        );
        challenges.push(`DPoP algs="${supportedAlgs.join(' ')}"`);
      }
    } else if (hasDpop && !hasBearer) {
      challenges.push(
        `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${supportedAlgs.join(
          ' '
        )}"`
      );
    } else {
      // Ambiguous: both present
      challenges.push(
        `DPoP error="${errorCode}", error_description="${safeDescription}", algs="${supportedAlgs.join(
          ' '
        )}"`
      );
      challenges.push(
        `Bearer error="${errorCode}", error_description="${safeDescription}"`
      );
    }
  }

  return challenges;
}
