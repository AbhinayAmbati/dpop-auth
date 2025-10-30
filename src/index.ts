/**
 * DPoP Auth - Device-bound authentication with Demonstration of Proof-of-Possession
 * 
 * A modern, simplified library for implementing DPoP authentication in Node.js applications.
 * Provides secure device-bound tokens, anti-replay protection, and Express middleware.
 * 
 * @author Abhinay Ambati
 * @version 1.1.0
 */

// Import types for the main API
import type { DPoPConfig, MiddlewareOptions, TokenResult, AuthFlowResult } from './types/index';
import type { Request, Response, NextFunction } from 'express';

// Core functionality - simplified exports
export { generateDPoPKeyPair, generateFingerprintHash } from './core/crypto';
export { MemoryReplayStore } from './core/dpop';
export { dpopAuth, optionalDPoPAuth } from './middleware/express';

// Export all types
export type * from './types/index';

/**
 * Simplified DPoP Authentication Client
 * 
 * This is the main class that provides a clean, modern API for DPoP authentication.
 * It handles all the complexity internally and provides simple methods for common use cases.
 */
export class DPoPAuth {
  private readonly config: Required<DPoPConfig>;
  private readonly secret: string;

  constructor(secret: string, config: Partial<DPoPConfig> = {}) {
    if (!secret || typeof secret !== 'string') {
      throw new Error('Secret key is required and must be a string');
    }
    
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
   * Generate device keys for client-side use
   * 
   * @returns Promise containing public/private key pair and thumbprint
   */
  async generateDeviceKeys() {
    const { generateDPoPKeyPair } = await import('./core/crypto');
    return generateDPoPKeyPair({ algorithm: this.config.algorithm });
  }

  /**
   * Create a complete authentication flow with simplified API
   * 
   * @param userId - User identifier
   * @param devicePublicKeyJwk - Device public key in JWK format
   * @param fingerprint - Optional device fingerprint
   * @returns Promise containing access token, refresh token, and expiration info
   */
  async createAuthFlow(
    userId: string,
    devicePublicKeyJwk: any,
    fingerprint?: string
  ): Promise<AuthFlowResult> {
    const { createAccessToken, createRefreshToken } = await import('./core/tokens');
    
    const [accessToken, refreshToken] = await Promise.all([
      createAccessToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint,
      }),
      createRefreshToken(userId, devicePublicKeyJwk, this.secret, {
        ...this.config,
        fingerprint,
        expiresIn: 7 * 24 * 60 * 60, // 7 days
      }),
    ]);
    
    return {
      accessToken,
      refreshToken,
      expiresIn: this.config.expiresIn,
      tokenType: 'DPoP',
    };
  }

  /**
   * Refresh access token using refresh token
   * 
   * @param refreshToken - Current refresh token
   * @param devicePublicKeyJwk - Device public key in JWK format
   * @param fingerprint - Optional device fingerprint
   * @returns Promise containing new access token
   */
  async refreshAccessToken(
    refreshToken: string,
    devicePublicKeyJwk: any,
    fingerprint?: string
  ): Promise<TokenResult> {
    const { verifyRefreshToken, createAccessToken } = await import('./core/tokens');
    
    // Verify refresh token
    const result = await verifyRefreshToken(refreshToken, this.secret, this.config);
    if (!result.valid || !result.payload) {
      throw new Error(`Invalid refresh token: ${result.error}`);
    }
    
    // Create new access token
    return createAccessToken(
      result.payload.sub,
      devicePublicKeyJwk,
      this.secret,
      {
        ...this.config,
        fingerprint,
      }
    );
  }

  /**
   * Create DPoP proof for client-side requests
   * 
   * @param httpMethod - HTTP method (GET, POST, etc.)
   * @param httpUri - Full HTTP URI
   * @param privateKey - Device private key
   * @param publicKeyJwk - Device public key in JWK format
   * @param accessToken - Optional access token to bind
   * @param fingerprint - Optional device fingerprint
   * @returns Promise containing DPoP proof JWT
   */
  async createDPoPProof(
    httpMethod: string,
    httpUri: string,
    privateKey: any,
    publicKeyJwk: any,
    accessToken?: string,
    fingerprint?: string
  ): Promise<string> {
    const { createDPoPProof } = await import('./core/dpop');
    
    return createDPoPProof(httpMethod, httpUri, privateKey, publicKeyJwk, {
      ...(accessToken && { accessToken }),
      ...(fingerprint && { fingerprint }),
      algorithm: this.config.algorithm,
    });
  }

  /**
   * Get Express middleware with current configuration
   * 
   * @param options - Optional middleware configuration overrides
   * @returns Express middleware function
   */
  middleware(options: Partial<MiddlewareOptions> = {}) {
    return async (req: Request, res: Response, next: NextFunction) => {
      const { dpopAuth } = await import('./middleware/express');
      const middleware = dpopAuth({
        secret: this.secret,
        ...this.config,
        ...options,
      });
      return middleware(req, res, next);
    };
  }

  /**
   * Verify an access token
   * 
   * @param token - Access token to verify
   * @returns Promise containing verification result
   */
  async verifyToken(token: string) {
    const { verifyAccessToken } = await import('./core/tokens');
    return verifyAccessToken(token, this.secret, this.config);
  }

  /**
   * Generate device fingerprint from request components
   * 
   * @param components - Fingerprint components (user agent, etc.)
   * @returns Fingerprint hash
   */
  generateFingerprint(components: Record<string, any>): string {
    const { generateFingerprintHash } = require('./core/crypto');
    return generateFingerprintHash(components);
  }

  /**
   * Get current configuration
   */
  getConfig(): Required<DPoPConfig> {
    return { ...this.config };
  }
}

/**
 * Default export for convenience
 */
export default DPoPAuth;

/**
 * Quick setup function for common use cases
 * 
 * @param secret - Secret key for token signing
 * @param config - Optional configuration
 * @returns New DPoPAuth instance
 */
export function createDPoPAuth(secret: string, config?: Partial<DPoPConfig>): DPoPAuth {
  return new DPoPAuth(secret, config);
}

/**
 * Create a simple, ready-to-use DPoP authentication setup
 * This is the recommended way to get started quickly
 * 
 * @param secret - Secret key for token signing
 * @param options - Optional configuration
 * @returns Object with auth instance and pre-configured middleware
 */
export async function createSimpleDPoPAuth(secret: string, options: Partial<DPoPConfig> = {}) {
  const auth = new DPoPAuth(secret, options);
  
  return {
    auth,
    middleware: auth.middleware(),
    generateDeviceKeys: () => auth.generateDeviceKeys(),
    createAuthFlow: (userId: string, deviceKey: any, fingerprint?: string) => 
      auth.createAuthFlow(userId, deviceKey, fingerprint),
    refreshToken: (refreshToken: string, deviceKey: any, fingerprint?: string) => 
      auth.refreshAccessToken(refreshToken, deviceKey, fingerprint),
  };
}

/**
 * Version information
 */
export const VERSION = '1.1.0';

/**
 * Library information
 */
export const INFO = {
  name: 'dpop-auth',
  version: VERSION,
  description: 'Modern device-bound authentication with DPoP tokens',
  author: 'Abhinay Ambati',
  license: 'Apache-2.0',
  repository: 'https://github.com/AbhinayAmbati/dpop-auth',
} as const;

// Legacy exports for backward compatibility
export {
  generateDPoPKeyPair as generateKeyPair,
} from './core/crypto';

export {
  createDPoPAuth as DPoPAuthClient,
};

// Advanced exports for power users
export {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from './core/tokens';

export {
  createDPoPProof,
  verifyDPoPProof,
} from './core/dpop';

export {
  requireDevice,
  requireUser,
  cleanupReplayStore,
} from './middleware/express';
