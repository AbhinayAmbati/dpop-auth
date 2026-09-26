import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import type {
  DPoPAlgorithm,
  KeyPairOptions,
  KeyPairResult,
  FingerprintComponents
} from '../types';
<<<<<<< HEAD
import { thumbprintCache, createJwkCacheKey, keyImportCache } from './cache';

/**
 * Extended algorithm type - kept as an alias for backwards compatibility
 * @deprecated Use DPoPAlgorithm instead, which now includes all supported algorithms
 */
export type ExtendedAlgorithm = DPoPAlgorithm;

/**
 * Algorithm to curve mapping for EC keys
 */
const EC_ALGORITHM_CURVES: Record<string, string> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};
=======
>>>>>>> parent of a5361f7 (updated the security, implement new algorithms, caching, rate limiting)

/**
 * Generate a cryptographic key pair for DPoP authentication
 */
<<<<<<< HEAD
export async function generateDPoPKeyPair(
  options: KeyPairOptions & { algorithm?: ExtendedAlgorithm } = {}
): Promise<KeyPairResult> {
  const { algorithm = 'ES256', keySize = 2048 } = options;
  let { curve } = options;
=======
export async function generateDPoPKeyPair(options: KeyPairOptions = {}) {
  const { algorithm = 'ES256', keySize = 2048, curve = 'P-256' } = options;
>>>>>>> parent of a5361f7 (updated the security, implement new algorithms, caching, rate limiting)

  let keyPair;

  if (algorithm === 'ES256') {
    keyPair = await generateKeyPair('ES256', {
      crv: curve,
      extractable: true,
    });
  } else if (algorithm === 'RS256') {
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
 */
export async function importDPoPKey(jwk: any, algorithm: DPoPAlgorithm) {
  try {
    const key = await importJWK(jwk, algorithm);
    const thumbprint = await calculateJwkThumbprint(jwk);

    return {
      key,
      thumbprint,
      jwk,
    };
  } catch (error) {
    throw new Error(`Failed to import key: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Calculate JWK thumbprint for device identification
 */
export async function getKeyThumbprint(jwk: any): Promise<string> {
  try {
    return await calculateJwkThumbprint(jwk);
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
  if (tolerance !== 0) {
    throw new Error(
      'Fuzzy fingerprint matching (tolerance > 0) is not yet implemented. ' +
      'Use tolerance = 0 for exact matching.'
    );
  }

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
