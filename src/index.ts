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

export { MemoryRevocationStore } from './core/token-utils';
export type { RevocationStore } from './core/token-utils';

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
import type { DPoPConfig, MiddlewareOptions, ReplayStore, AccessTokenPayload } from './types';
import type { RevocationStore } from './core/token-utils';

// Utility functions for common use cases
import { createAccessToken, createRefreshToken, verifyAccessToken, verifyRefreshToken } from './core/tokens';
import { getKeyThumbprint } from './core/crypto';
import { DPoPError, DPoPErrorCode } from './core/errors';
import { dpopAuth as dpopAuthMiddleware } from './middleware/express';

/**
 * Options for the DPoPAuth utility class
 */
export interface DPoPAuthOptions extends Partial<DPoPConfig> {
  /** Optional replay store for DPoP proof anti-replay protection */
  replayStore?: ReplayStore;
  /** Optional revocation store for token revocation */
  revocationStore?: RevocationStore;
}

export class DPoPAuth {
  private config: Required<DPoPConfig>;
  private secret: string;
  private replayStore: ReplayStore | undefined;
  private revocationStore: RevocationStore | undefined;

  constructor(secret: string, options: DPoPAuthOptions = {}) {
    const { replayStore, revocationStore, ...config } = options;

    this.secret = secret;
    this.replayStore = replayStore;
    this.revocationStore = revocationStore;
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
      thumbprint,
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
   * Verify a token (signature, expiry and revocation status)
   */
  async verifyToken(token: string): Promise<{
    valid: boolean;
    payload?: AccessTokenPayload;
    error?: string;
  }> {
    const result = await verifyAccessToken(token, this.secret, this.config);
    if (!result.valid || !result.payload) {
      return { valid: false, error: result.error || 'Invalid access token' };
    }

    if (this.revocationStore && (await this.revocationStore.isRevoked(result.payload.jti))) {
      return { valid: false, error: 'Token has been revoked' };
    }

    return { valid: true, payload: result.payload };
  }

  /**
   * Get Express middleware with current configuration
   */
  getMiddleware(options: Partial<MiddlewareOptions> = {}) {
    return dpopAuthMiddleware({
      secret: this.secret,
      ...this.config,
      ...(this.replayStore ? { replayStore: this.replayStore } : {}),
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
export function createDPoPAuth(secret: string, options?: DPoPAuthOptions) {
  return new DPoPAuth(secret, options);
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
