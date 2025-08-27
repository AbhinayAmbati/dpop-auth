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
  DPoPRequest,
} from './types';

// Import types for the utility class
import type { DPoPConfig, MiddlewareOptions } from './types';

// Utility functions for common use cases
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
    const { createAccessToken, createRefreshToken } = await import('./core/tokens');
    
    const [accessToken, refreshToken] = await Promise.all([
      createAccessToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint: fingerprint || undefined,
      }),
      createRefreshToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint: fingerprint || undefined,
        expiresIn: 7 * 24 * 60 * 60, // 7 days
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
    const { verifyRefreshToken, createAccessToken } = await import('./core/tokens');
    
    // Verify refresh token
    const result = await verifyRefreshToken(refreshToken, this.secret, this.config);
    if (!result.valid) {
      throw new Error(`Invalid refresh token: ${result.error}`);
    }
    
    const payload = result.payload!;
    
    // Create new access token
    const accessToken = await createAccessToken(
      payload.sub,
      devicePublicKeyJwk,
      this.secret,
      {
        ...this.config,
        fingerprint: fingerprint || undefined,
      }
    );
    
    return accessToken;
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
