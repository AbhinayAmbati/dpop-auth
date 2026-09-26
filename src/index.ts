/**
 * DPoP Auth - Device-bound authentication with Demonstration of Proof-of-Possession
 * 
 * A comprehensive library for implementing DPoP authentication in Node.js applications.
 * Provides secure device-bound tokens, anti-replay protection, and Express middleware.
 * 
 * @author Abhinay Ambati
 * @version 1.0.0
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

// Express middleware
export {
  dpopAuth,
  optionalDPoPAuth,
  requireDevice,
  requireUser,
  cleanupReplayStore,
} from './middleware/express';

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
  KeyPairResult,
  DPoPRequest,
} from './types';

// Import types for the utility class
import type { DPoPConfig, MiddlewareOptions } from './types';

// Utility functions for common use cases
import { createAccessToken, createRefreshToken, verifyRefreshToken } from './core/tokens';
import { getKeyThumbprint } from './core/crypto';
<<<<<<< HEAD
import { validateSecretStrength } from './core/security';
import { DPoPError, DPoPErrorCode } from './core/errors';
import { dpopAuth as dpopAuthMiddleware } from './middleware/express';
=======
>>>>>>> parent of a5361f7 (updated the security, implement new algorithms, caching, rate limiting)

export class DPoPAuth {
  private config: Required<DPoPConfig>;
  private secret: string;

  constructor(secret: string, config: Partial<DPoPConfig> = {}) {
    this.secret = secret;
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
   * Create a complete authentication flow
   */
  async createAuthFlow(
    userId: string,
    devicePublicKeyJwk: any,
    fingerprint?: string
  ) {
    // Calculate thumbprint once for efficiency
    const thumbprint = await getKeyThumbprint(devicePublicKeyJwk);

    const [accessToken, refreshToken] = await Promise.all([
      createAccessToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint: fingerprint || undefined,
        thumbprint,
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
      expiresIn: this.config.expiresIn,
    };
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
      throw new Error(`Invalid refresh token: ${result.error}`);
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
<<<<<<< HEAD
   * Revoke a token
   */
  async revokeToken(token: string): Promise<boolean> {
    if (!this.revocationStore) {
      throw new DPoPError(
        DPoPErrorCode.CONFIG_MISSING_STORE,
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
=======
>>>>>>> parent of a5361f7 (updated the security, implement new algorithms, caching, rate limiting)
   * Get Express middleware with current configuration
   */
  getMiddleware(options: Partial<MiddlewareOptions> = {}) {
    return dpopAuthMiddleware({
      secret: this.secret,
      ...this.config,
<<<<<<< HEAD
      ...(this.replayStore ? { replayStore: this.replayStore } : {}),
=======
>>>>>>> parent of a5361f7 (updated the security, implement new algorithms, caching, rate limiting)
      ...options,
    });
  }

  /**
   * Clean up internal resources (timers, stores)
   * Call this in tests or serverless environments to prevent memory leaks
   */
  destroy(): void {
    if (this.replayStore && 'stopCleanup' in this.replayStore) {
      (this.replayStore as any).stopCleanup();
    }
    if (this.revocationStore && 'stop' in this.revocationStore) {
      (this.revocationStore as any).stop();
    }
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
export const VERSION = '1.0.0';

/**
 * Library information
 */
export const INFO = {
  name: 'dpop-auth',
  version: VERSION,
  description: 'Device-bound authentication with DPoP tokens',
  author: 'Abhinay Ambati',
  license: 'Apache-2.0',
  repository: 'https://github.com/abhinayambati/dpop-auth',
} as const;
