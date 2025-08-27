import type { Request, Response, NextFunction } from 'express';
import type {
  MiddlewareOptions,
  DPoPRequest,
  ReplayStore
} from '../types';
import {
  verifyAccessToken
} from '../core/tokens';
import { 
  verifyDPoPProof, 
  MemoryReplayStore 
} from '../core/dpop';
import { 
  generateFingerprintHash,
  validateFingerprintComponents 
} from '../core/crypto';

// Extend Express Request type
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-interface
    interface Request extends DPoPRequest {}
  }
}

/**
 * Default replay store for development
 */
const defaultReplayStore = new MemoryReplayStore();

/**
 * Express middleware for DPoP authentication
 */
export function dpopAuth(options: MiddlewareOptions) {
  if (!options?.secret) {
    throw new Error('Secret is required for DPoP authentication');
  }

  const {
    secret,
    replayStore = defaultReplayStore,
    skipDPoP = false,
    onError,
    ...config
  } = options;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Extract Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return handleError(
          new Error('Missing or invalid Authorization header'),
          req, res, next, onError
        );
      }

      const accessToken = authHeader.substring(7);
      if (!accessToken) {
        return handleError(
          new Error('Empty access token'),
          req, res, next, onError
        );
      }

      // Verify access token
      const tokenResult = await verifyAccessToken(accessToken, secret, config);
      if (!tokenResult?.valid || !tokenResult.payload) {
        return handleError(
          new Error(`Invalid access token: ${tokenResult?.error || 'Unknown error'}`),
          req, res, next, onError
        );
      }

      const tokenPayload = tokenResult.payload;
      req.token = tokenPayload;

      // Skip DPoP validation if requested (for testing)
      if (skipDPoP) {
        return next();
      }

      // Extract DPoP header
      const dpopHeader = req.headers['dpop'] as string;
      if (!dpopHeader) {
        return handleError(
          new Error('Missing DPoP header'),
          req, res, next, onError
        );
      }

      // Build HTTP URI for DPoP validation
      const protocol = req.secure ? 'https' : 'http';
      const host = req.get('host') || 'localhost';
      const httpUri = `${protocol}://${host}${req.originalUrl}`;

      // Generate fingerprint from request
      let fingerprint: string | undefined;
      if (config.enableFingerprinting) {
        const fingerprintComponents = extractFingerprintComponents(req);
        const validation = validateFingerprintComponents(fingerprintComponents);
        
        if (!validation?.valid) {
          return handleError(
            new Error(`Invalid fingerprint components: ${validation?.errors?.join(', ') || 'Unknown error'}`),
            req, res, next, onError
          );
        }
        
        fingerprint = generateFingerprintHash(fingerprintComponents);
        req.fingerprint = fingerprint;
      }

      // Verify DPoP proof
      const dpopResult = await verifyDPoPProof(
        dpopHeader,
        req.method,
        httpUri,
        {
          ...config,
          accessToken,
          expectedFingerprint: fingerprint || undefined,
          replayStore,
        }
      );

      if (!dpopResult?.valid || !dpopResult.thumbprint) {
        return handleError(
          new Error(`Invalid DPoP proof: ${dpopResult?.error || 'Unknown error'}`),
          req, res, next, onError
        );
      }

      // Verify device key binding
      const tokenThumbprint = tokenPayload.cnf?.jkt;
      const dpopThumbprint = dpopResult.thumbprint;

      if (!tokenThumbprint || tokenThumbprint !== dpopThumbprint) {
        return handleError(
          new Error('Device key mismatch between token and DPoP proof'),
          req, res, next, onError
        );
      }

      // Verify fingerprint binding if enabled
      if (config.enableFingerprinting && tokenPayload.fph && fingerprint) {
        if (tokenPayload.fph !== fingerprint) {
          return handleError(
            new Error('Fingerprint mismatch between token and request'),
            req, res, next, onError
          );
        }
      }

      // Store DPoP information in request
      if (dpopResult.payload) {
        req.dpop = dpopResult.payload;
      }
      req.thumbprint = dpopThumbprint;

      next();
    } catch (error) {
      handleError(
        error instanceof Error ? error : new Error('Authentication failed'),
        req, res, next, onError
      );
    }
  };
}

/**
 * Middleware for optional DPoP authentication
 */
export function optionalDPoPAuth(options: MiddlewareOptions) {
  const middleware = dpopAuth(options);
  
  return (req: Request, res: Response, next: NextFunction) => {
    // If no authorization header, skip authentication
    if (!req.headers.authorization) {
      return next();
    }
    
    // Otherwise, require full authentication
    return middleware(req, res, next);
  };
}

/**
 * Middleware to require specific device binding
 */
export function requireDevice(expectedThumbprint: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.thumbprint) {
      return res.status(401).json({
        error: 'Device authentication required',
        code: 'DEVICE_AUTH_REQUIRED'
      });
    }
    
    if (req.thumbprint !== expectedThumbprint) {
      return res.status(403).json({
        error: 'Device not authorized',
        code: 'DEVICE_NOT_AUTHORIZED'
      });
    }

    return next();
  };
}

/**
 * Middleware to require specific user
 */
export function requireUser(expectedUserId: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.token) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    if (req.token.sub !== expectedUserId) {
      return res.status(403).json({
        error: 'User not authorized',
        code: 'USER_NOT_AUTHORIZED'
      });
    }

    return next();
  };
}

/**
 * Extract fingerprint components from Express request
 */
function extractFingerprintComponents(req: Request) {
  return {
    userAgent: req.get('user-agent'),
    acceptLanguage: req.get('accept-language'),
    acceptEncoding: req.get('accept-encoding'),
    // Add more components as needed
    xForwardedFor: req.get('x-forwarded-for'),
    xRealIp: req.get('x-real-ip'),
  };
}

/**
 * Handle authentication errors
 */
function handleError(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction,
  onError?: (error: Error, req: any, res: any, next: any) => void
) {
  if (onError) {
    return onError(error, req, res, next);
  }
  
  // Default error handling
  const statusCode = error.message.includes('Missing') ? 401 : 403;
  
  res.status(statusCode).json({
    error: 'Authentication failed',
    message: error.message,
    code: 'DPOP_AUTH_FAILED'
  });
}

/**
 * Cleanup middleware for replay store
 */
export function cleanupReplayStore(replayStore: ReplayStore, intervalMs: number = 300000) {
  const interval = setInterval(async () => {
    try {
      await replayStore.cleanup();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Failed to cleanup replay store:', error);
    }
  }, intervalMs);

  // Return cleanup function
  return () => clearInterval(interval);
}
