import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import type { 
  DPoPAlgorithm, 
  KeyPairOptions, 
  FingerprintComponents 
} from '../types';

/**
 * Generate a cryptographic key pair for DPoP authentication
 */
export async function generateDPoPKeyPair(options: KeyPairOptions = {}) {
  const { algorithm = 'ES256', keySize = 2048, curve = 'P-256' } = options;

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
 * Validate fingerprint components
 */
export function validateFingerprintComponents(components: FingerprintComponents): {
  valid: boolean;
  errors?: string[];
} {
  const errors: string[] = [];
  
  if (!components || typeof components !== 'object') {
    errors.push('Components must be an object');
    return { valid: false, errors };
  }
  
  const validKeys = Object.keys(components).filter(key => {
    const value = components[key];
    return value !== undefined && value !== null && value !== '';
  });
  
  if (validKeys.length === 0) {
    errors.push('At least one valid component is required');
  }
  
  return { valid: errors.length === 0, ...(errors.length > 0 && { errors }) };
}

/**
 * Compare two fingerprint hashes
 */
export function compareFingerprintHashes(hash1: string, hash2: string): boolean {
  if (!hash1 || !hash2) return false;
  return hash1 === hash2;
}

/**
 * Validate timestamp with clock tolerance
 */
export function validateTimestamp(timestamp: number, clockTolerance: number = 60): {
  valid: boolean;
  error?: string;
} {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);
  
  if (diff > clockTolerance) {
    return {
      valid: false,
      error: `Timestamp too far from current time (${diff}s > ${clockTolerance}s)`,
    };
  }
  
  return { valid: true };
}

/**
 * Create a secure hash of any string
 */
export function createSecureHash(input: string, algorithm: 'sha256' | 'sha512' = 'sha256'): string {
  return createHash(algorithm)
    .update(input)
    .digest('hex');
}

/**
 * Validate fingerprint components for security
 */
export function validateFingerprintComponentsForSecurity(components: FingerprintComponents): {
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
    const botPatterns = [
      /bot|crawler|spider|scraper/i,
      /curl|wget|python|java/i,
      /headless|phantom|selenium/i
    ];
    
    if (botPatterns.some(pattern => pattern.test(ua))) {
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

