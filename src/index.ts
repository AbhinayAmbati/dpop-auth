/**
 * DPoP Auth - Device-bound authentication with Demonstration of Proof-of-Possession
 * 
 * A comprehensive library for implementing DPoP authentication in Node.js applications.
 * Provides secure device-bound tokens, anti-replay protection, and Express middleware.
 * 
 * @author Abhinay Ambati
 * @version 2.0.0
 */

// Core functionality
export {
  generateDPoPKeyPair,
  importDPoPKey,
  getKeyThumbprint,
  generateJTI,
  generateSecureRandom,
  createAccessTokenHash,
  generateFingerprintHash,
  validateFingerprintComponents,
  compareFingerprintHashes,
  validateTimestamp,
  createSecureHash,
  type ExtendedAlgorithm,
} from './core/crypto';

export {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  extractThumbprintFromToken,
  isTokenExpired,
} from './core/tokens';

export {
  createDPoPProof,
  verifyDPoPProof,
  extractPublicKeyFromDPoP,
  extractThumbprintFromDPoP,
  validateDPoPFormat,
  MemoryReplayStore,
} from './core/dpop';

// Error handling
export {
  DPoPErrorCode,
  DPoPError,
  Errors,
} from './core/errors';

// Cache utilities
export {
  LRUCache,
  thumbprintCache,
  keyImportCache,
  createJwkCacheKey,
} from './core/cache';

// Rate limiting
export {
  SlidingWindowRateLimiter,
  TokenBucketRateLimiter,
  createRateLimiterMiddleware,
  type RateLimiterConfig,
  type RateLimiterResult,
} from './core/rate-limiter';

// Token utilities
export {
  introspectToken,
  MemoryRevocationStore,
  TokenRotationManager,
  validateTokenStructure,
  getTokenLifetime,
  type TokenIntrospectionResult,
  type RevocationStore,
} from './core/token-utils';

// Security utilities
export {
  secureCompare,
  secureCompareBuffers,
  generateSecureBytes,
  generateSecureString,
  createHmacHash,
  validateSecretStrength,
  sanitizeForLogging,
  maskSensitiveData,
  validateJwkSecurity,
  IPUtils,
  createRequestSignature,
  verifyRequestSignature,
} from './core/security';

// Express middleware
export {
  dpopAuth,
  optionalDPoPAuth,
  requireDevice,
  requireUser,
  cleanupReplayStore,
} from './middleware/express';

// Redis stores (for production)
export {
  RedisReplayStore,
  RedisRevocationStore,
  RedisNonceStore,
  RedisDeviceRegistry,
  type RedisClient,
  type RedisStoreConfig,
} from './stores/redis';

// Types
export type {
  DPoPAlgorithm,
  DPoPConfig,
  DPoPHeader,
  DPoPPayload,
  AccessTokenPayload,
  RefreshTokenPayload,
  TokenResult,
  DPoPVerificationResult,
  TokenVerificationResult,
  FingerprintComponents,
  ReplayStore,
  MiddlewareOptions,
  KeyPairOptions,
  DPoPRequest,
} from './types';

// Import types for the utility class
import type { DPoPConfig, MiddlewareOptions, ReplayStore } from './types';
import type { RevocationStore } from './core/token-utils';

// Utility functions for common use cases
import { createAccessToken, createRefreshToken, verifyRefreshToken, verifyAccessToken } from './core/tokens';
import { getKeyThumbprint } from './core/crypto';
import { validateSecretStrength } from './core/security';
import { DPoPError, DPoPErrorCode } from './core/errors';

/**
 * Main DPoP authentication class with enhanced features
 */
export class DPoPAuth {
  private config: Required<DPoPConfig>;
  private secret: string;
  private replayStore: ReplayStore | undefined;
  private revocationStore: RevocationStore | undefined;

  constructor(secret: string, config: Partial<DPoPConfig> & {
    replayStore?: ReplayStore;
    revocationStore?: RevocationStore;
    validateSecret?: boolean;
  } = {}) {
    // Validate secret strength if enabled (default: true in production)
    if (config.validateSecret !== false) {
      const validation = validateSecretStrength(secret);
      if (!validation.valid && process.env['NODE_ENV'] === 'production') {
        throw new DPoPError(
          DPoPErrorCode.CONFIG_MISSING_SECRET,
          `Weak secret: ${validation.issues.join(', ')}`,
          500
        );
      }
    }

    this.secret = secret;
    this.replayStore = config.replayStore;
    this.revocationStore = config.revocationStore;

    this.config = {
      algorithm: 'ES256',
      expiresIn: 300,
      clockTolerance: 60,
      maxAge: 300,
      enableFingerprinting: true,
      issuer: 'dpop-auth',
      audience: 'dpop-auth',
      ...config,
    };
  }

  /**
   * Get the current configuration
   */
  getConfig(): Readonly<DPoPConfig> {
    return { ...this.config };
  }

  /**
   * Create a complete authentication flow
   */
  async createAuthFlow(
    userId: string,
    devicePublicKeyJwk: any,
    fingerprint?: string,
    customClaims?: Record<string, any>
  ) {
    // Calculate thumbprint once for efficiency
    const thumbprint = await getKeyThumbprint(devicePublicKeyJwk);

    const [accessToken, refreshToken] = await Promise.all([
      createAccessToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint: fingerprint || undefined,
        thumbprint,
        ...(customClaims ? { customClaims } : {}),
      }),
      createRefreshToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint: fingerprint || undefined,
        expiresIn: 7 * 24 * 60 * 60, // 7 days
        thumbprint,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      thumbprint,
      expiresIn: this.config.expiresIn,
    };
  }

  /**
   * Verify an access token
   */
  async verifyToken(token: string) {
    const result = await verifyAccessToken(token, this.secret, this.config);

    if (!result.valid) {
      return result;
    }

    // Check revocation if store is configured
    if (this.revocationStore && result.payload?.jti) {
      const isRevoked = await this.revocationStore.isRevoked(result.payload.jti);
      if (isRevoked) {
        return {
          valid: false,
          error: 'Token has been revoked',
        };
      }
    }

    return result;
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(
    refreshToken: string,
    devicePublicKeyJwk: any,
    fingerprint?: string
  ) {
    // Verify refresh token
    const result = await verifyRefreshToken(refreshToken, this.secret, this.config);
    if (!result.valid) {
      throw new DPoPError(
        DPoPErrorCode.AUTH_TOKEN_INVALID,
        `Invalid refresh token: ${result.error}`,
        401
      );
    }

    const payload = result.payload!;

    // Calculate thumbprint for new token
    const thumbprint = await getKeyThumbprint(devicePublicKeyJwk);

    // Create new access token
    const accessToken = await createAccessToken(
      payload.sub,
      devicePublicKeyJwk,
      this.secret,
      {
        ...this.config,
        fingerprint: fingerprint || undefined,
        thumbprint,
      }
    );

    return accessToken;
  }

  /**
   * Revoke a token
   */
  async revokeToken(token: string): Promise<boolean> {
    if (!this.revocationStore) {
      throw new DPoPError(
        DPoPErrorCode.CONFIG_MISSING_SECRET,
        'Revocation store is not configured',
        500
      );
    }

    const result = await verifyAccessToken(token, this.secret, this.config);
    if (!result.valid || !result.payload) {
      return false;
    }

    await this.revocationStore.revoke(result.payload.jti, result.payload.exp);
    return true;
  }

  /**
   * Get Express middleware with current configuration
   */
  getMiddleware(options: Partial<MiddlewareOptions> = {}) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { dpopAuth } = require('./middleware/express');

    return dpopAuth({
      secret: this.secret,
      ...this.config,
      replayStore: this.replayStore,
      ...options,
    });
  }
}

// Default export for convenience
export default DPoPAuth;

/**
 * Quick setup function for common use cases
 */
export function createDPoPAuth(secret: string, config?: Partial<DPoPConfig>) {
  return new DPoPAuth(secret, config);
}

/**
 * Version information
 */
export const VERSION = '2.0.0';

/**
 * Library information
 */
export const INFO = {
  name: 'dpop-auth',
  version: VERSION,
  description: 'Device-bound authentication with DPoP tokens - Enhanced security edition',
  author: 'Abhinay Ambati',
  license: 'Apache-2.0',
  repository: 'https://github.com/abhinayambati/dpop-auth',
  features: [
    'Device-bound tokens',
    'Anti-replay protection',
    'Fingerprint binding',
    'Rate limiting',
    'Token revocation',
    'Redis support',
    'TypeScript native',
  ],
} as const;
