import { SignJWT, jwtVerify, KeyLike } from 'jose';
import type {
  DPoPConfig,
  AccessTokenPayload,
  RefreshTokenPayload,
  TokenResult,
  TokenVerificationResult
} from '../types';
import { generateJTI, getKeyThumbprint } from './crypto';

/**
 * Default configuration for DPoP tokens
 */
const DEFAULT_CONFIG: Required<DPoPConfig> = {
  algorithm: 'ES256',
  expiresIn: 300, // 5 minutes
  clockTolerance: 60, // 1 minute
  maxAge: 300, // 5 minutes
  enableFingerprinting: true,
  issuer: 'dpop-auth',
  audience: 'dpop-auth',
};

/**
 * Create an access token bound to a device key
 */
export async function createAccessToken(
  subject: string,
  devicePublicKeyJwk: any,
  secret: string | KeyLike,
  options: Partial<DPoPConfig> & {
    fingerprint?: string | undefined;
    customClaims?: Record<string, any>;
  } = {}
): Promise<TokenResult> {
  const config = { ...DEFAULT_CONFIG, ...options };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + config.expiresIn;
  const jti = generateJTI();
  
  // Get device key thumbprint
  const thumbprint = await getKeyThumbprint(devicePublicKeyJwk);
  
  // Build payload
  const payload: AccessTokenPayload = {
    sub: subject,
    iat: now,
    exp,
    jti,
    iss: config.issuer,
    aud: config.audience,
    cnf: {
      jkt: thumbprint,
    },
    ...options.customClaims,
  };
  
  // Add fingerprint if provided and enabled
  if (config.enableFingerprinting && options.fingerprint) {
    payload.fph = options.fingerprint;
  }
  
  // Create and sign JWT
  const algorithm = typeof secret === 'string' ? 'HS256' : config.algorithm;
  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' });
  
  // Import secret if it's a string
  let signingKey: KeyLike;
  if (typeof secret === 'string') {
    // For string secrets, create a symmetric key
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    signingKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  } else {
    signingKey = secret;
  }
  
  const token = await jwt.sign(signingKey);
  
  return {
    token,
    expiresAt: exp * 1000, // Convert to milliseconds
    jti,
  };
}

/**
 * Create a refresh token bound to a device key
 */
export async function createRefreshToken(
  subject: string,
  devicePublicKeyJwk: any,
  secret: string | KeyLike,
  options: Partial<DPoPConfig> & {
    fingerprint?: string | undefined;
    expiresIn?: number; // Override for longer expiration
  } = {}
): Promise<TokenResult> {
  const config = { ...DEFAULT_CONFIG, ...options };
  const refreshExpiresIn = options.expiresIn || (7 * 24 * 60 * 60); // 7 days default
  const now = Math.floor(Date.now() / 1000);
  const exp = now + refreshExpiresIn;
  const jti = generateJTI();
  
  // Get device key thumbprint
  const thumbprint = await getKeyThumbprint(devicePublicKeyJwk);
  
  // Build payload
  const payload: RefreshTokenPayload = {
    sub: subject,
    iat: now,
    exp,
    jti,
    iss: config.issuer,
    aud: config.audience,
    typ: 'refresh',
    cnf: {
      jkt: thumbprint,
    },
  };
  
  // Add fingerprint if provided and enabled
  if (config.enableFingerprinting && options.fingerprint) {
    payload.fph = options.fingerprint;
  }
  
  // Create and sign JWT
  const algorithm = typeof secret === 'string' ? 'HS256' : config.algorithm;
  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' });

  // Import secret if it's a string
  let signingKey: KeyLike;
  if (typeof secret === 'string') {
    // For string secrets, create a symmetric key
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    signingKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  } else {
    signingKey = secret;
  }
  
  const token = await jwt.sign(signingKey);
  
  return {
    token,
    expiresAt: exp * 1000, // Convert to milliseconds
    jti,
  };
}

/**
 * Verify an access token
 */
export async function verifyAccessToken(
  token: string,
  secret: string | KeyLike,
  options: Partial<DPoPConfig> = {}
): Promise<TokenVerificationResult> {
  const config = { ...DEFAULT_CONFIG, ...options };
  
  try {
    // Import secret if it's a string
    let verificationKey: KeyLike;
    if (typeof secret === 'string') {
      // For string secrets, create a symmetric key
      const encoder = new TextEncoder();
      const keyData = encoder.encode(secret);
      verificationKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );
    } else {
      verificationKey = secret;
    }
    
    const { payload } = await jwtVerify(token, verificationKey, {
      issuer: config.issuer,
      audience: config.audience,
      clockTolerance: config.clockTolerance,
    });
    
    // Validate required claims
    const accessTokenPayload = payload as AccessTokenPayload;
    
    if (!accessTokenPayload.cnf?.jkt) {
      return {
        valid: false,
        error: 'Missing device key thumbprint (cnf.jkt)',
      };
    }
    
    return {
      valid: true,
      payload: accessTokenPayload,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Token verification failed',
    };
  }
}

/**
 * Verify a refresh token
 */
export async function verifyRefreshToken(
  token: string,
  secret: string | KeyLike,
  options: Partial<DPoPConfig> = {}
): Promise<TokenVerificationResult> {
  const config = { ...DEFAULT_CONFIG, ...options };
  
  try {
    // Import secret if it's a string
    let verificationKey: KeyLike;
    if (typeof secret === 'string') {
      // For string secrets, create a symmetric key
      const encoder = new TextEncoder();
      const keyData = encoder.encode(secret);
      verificationKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );
    } else {
      verificationKey = secret;
    }
    
    const { payload } = await jwtVerify(token, verificationKey, {
      issuer: config.issuer,
      audience: config.audience,
      clockTolerance: config.clockTolerance,
    });
    
    // Validate required claims
    const refreshTokenPayload = payload as RefreshTokenPayload;
    
    if (refreshTokenPayload.typ !== 'refresh') {
      return {
        valid: false,
        error: 'Invalid token type, expected refresh token',
      };
    }
    
    if (!refreshTokenPayload.cnf?.jkt) {
      return {
        valid: false,
        error: 'Missing device key thumbprint (cnf.jkt)',
      };
    }
    
    return {
      valid: true,
      payload: refreshTokenPayload,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Token verification failed',
    };
  }
}

/**
 * Extract device key thumbprint from token without full verification
 */
export function extractThumbprintFromToken(token: string): string | null {
  try {
    // Decode JWT payload without verification (for thumbprint extraction only)
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    return payload.cnf?.jkt || null;
  } catch {
    return null;
  }
}

/**
 * Check if token is expired (without full verification)
 */
export function isTokenExpired(token: string, clockTolerance: number = 60): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return true;
    
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    const now = Math.floor(Date.now() / 1000);
    
    return !payload.exp || (payload.exp + clockTolerance) < now;
  } catch {
    return true;
  }
}
