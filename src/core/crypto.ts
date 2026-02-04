import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import type {
  DPoPAlgorithm,
  KeyPairOptions,
  FingerprintComponents
} from '../types';
import { thumbprintCache, createJwkCacheKey, keyImportCache } from './cache';

/**
 * Extended algorithm support including ES384, ES512, PS256
 */
export type ExtendedAlgorithm = DPoPAlgorithm | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';

/**
 * Algorithm to curve mapping for EC keys
 */
const EC_ALGORITHM_CURVES: Record<string, string> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

/**
 * Generate a cryptographic key pair for DPoP authentication
 * Supports: ES256, ES384, ES512, RS256, PS256, PS384, PS512
 */
export async function generateDPoPKeyPair(options: KeyPairOptions & { algorithm?: ExtendedAlgorithm } = {}) {
  const { algorithm = 'ES256', keySize = 2048 } = options;
  let { curve } = options;

  let keyPair;

  // EC algorithms
  if (algorithm.startsWith('ES')) {
    // Auto-select curve based on algorithm if not specified
    if (!curve) {
      curve = EC_ALGORITHM_CURVES[algorithm] || 'P-256';
    }
    keyPair = await generateKeyPair(algorithm, {
      crv: curve,
      extractable: true,
    });
  }
  // RSA-PSS algorithms  
  else if (algorithm.startsWith('PS')) {
    keyPair = await generateKeyPair(algorithm, {
      modulusLength: keySize,
      extractable: true,
    });
  }
  // RSA PKCS#1 v1.5
  else if (algorithm === 'RS256') {
    keyPair = await generateKeyPair('RS256', {
      modulusLength: keySize,
      extractable: true,
    });
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const publicKeyJwk = await exportJWK(keyPair.publicKey);
  const privateKeyJwk = await exportJWK(keyPair.privateKey);
  const thumbprint = await calculateJwkThumbprint(publicKeyJwk);

  // Cache the thumbprint
  const cacheKey = createJwkCacheKey(publicKeyJwk);
  thumbprintCache.set(cacheKey, thumbprint);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyJwk,
    privateKeyJwk,
    thumbprint,
    algorithm,
  };
}

/**
 * Import a JWK key for cryptographic operations
 * Uses caching for improved performance
 */
export async function importDPoPKey(jwk: any, algorithm: DPoPAlgorithm | ExtendedAlgorithm) {
  try {
    const cacheKey = `${createJwkCacheKey(jwk)}:${algorithm}`;

    // Check cache first
    const cached = keyImportCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const key = await importJWK(jwk, algorithm);
    const thumbprint = await getKeyThumbprint(jwk);

    const result = {
      key,
      thumbprint,
      jwk,
    };

    // Cache the result
    keyImportCache.set(cacheKey, result);

    return result;
  } catch (error) {
    throw new Error(`Failed to import key: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Calculate JWK thumbprint for device identification
 * Uses caching for improved performance
 */
export async function getKeyThumbprint(jwk: any): Promise<string> {
  try {
    // Check cache first
    const cacheKey = createJwkCacheKey(jwk);
    const cached = thumbprintCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const thumbprint = await calculateJwkThumbprint(jwk);

    // Cache the result
    thumbprintCache.set(cacheKey, thumbprint);

    return thumbprint;
  } catch (error) {
    throw new Error(`Failed to calculate thumbprint: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Generate a secure random JWT ID
 */
export function generateJTI(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Generate a secure random string
 */
export function generateSecureRandom(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Create a hash of the access token for DPoP binding
 */
export function createAccessTokenHash(accessToken: string): string {
  return createHash('sha256')
    .update(accessToken)
    .digest('base64url');
}

/**
 * Generate a device fingerprint hash from components
 */
export function generateFingerprintHash(components: FingerprintComponents): string {
  // Sort keys for consistent hashing
  const sortedKeys = Object.keys(components).sort();
  const normalizedComponents: Record<string, string> = {};

  // Normalize and filter components
  for (const key of sortedKeys) {
    const value = components[key];
    if (value !== undefined && value !== null && value !== '') {
      // Convert to string and normalize
      normalizedComponents[key] = String(value).toLowerCase().trim();
    }
  }

  // Create deterministic string representation
  const fingerprintString = JSON.stringify(normalizedComponents);

  // Generate SHA-256 hash
  return createHash('sha256')
    .update(fingerprintString)
    .digest('hex');
}

/**
 * Validate fingerprint components for security
 */
const BOT_PATTERNS = [
  /bot|crawler|spider|scraper/i,
  /curl|wget|python|java/i,
  /headless|phantom|selenium/i
];

export function validateFingerprintComponents(components: FingerprintComponents): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check for minimum required components
  const requiredComponents = ['userAgent'];
  for (const component of requiredComponents) {
    if (!components[component]) {
      errors.push(`Missing required component: ${component}`);
    }
  }

  // Validate user agent
  if (components.userAgent) {
    const ua = components.userAgent;
    if (ua.length < 10 || ua.length > 1000) {
      errors.push('User agent length is suspicious');
    }

    // Check for common bot patterns
    if (BOT_PATTERNS.some(pattern => pattern.test(ua))) {
      errors.push('User agent indicates automated client');
    }
  }

  // Validate timezone offset
  if (components.timezoneOffset !== undefined) {
    const offset = Number(components.timezoneOffset);
    if (isNaN(offset) || offset < -720 || offset > 720) {
      errors.push('Invalid timezone offset');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Compare two fingerprint hashes with tolerance for minor changes
 */
export function compareFingerprintHashes(
  hash1: string,
  hash2: string,
  tolerance: number = 0
): boolean {
  if (tolerance === 0) {
    return hash1 === hash2;
  }

  // For future implementation: fuzzy matching with Hamming distance
  // Currently just exact match
  return hash1 === hash2;
}

/**
 * Validate timestamp with clock skew tolerance
 */
export function validateTimestamp(
  timestamp: number,
  clockTolerance: number = 60
): { valid: boolean; error?: string } {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);

  if (diff > clockTolerance) {
    return {
      valid: false,
      error: `Timestamp outside acceptable range. Difference: ${diff}s, tolerance: ${clockTolerance}s`
    };
  }

  return { valid: true };
}

/**
 * Create a secure hash of multiple values
 */
export function createSecureHash(...values: string[]): string {
  const hash = createHash('sha256');
  for (const value of values) {
    hash.update(value);
  }
  return hash.digest('hex');
}
