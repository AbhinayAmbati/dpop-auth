import { SignJWT, jwtVerify, importJWK, KeyLike, decodeProtectedHeader, decodeJwt } from 'jose';
import type {
  DPoPConfig,
  DPoPPayload,
  DPoPVerificationResult,
  DPoPAlgorithm,
  ReplayStore
} from '../types';
import {
  generateJTI,
  getKeyThumbprint,
  createAccessTokenHash,
  validateTimestamp
} from './crypto';

/**
 * Default configuration for DPoP proofs
 */
const DEFAULT_CONFIG: Required<DPoPConfig> = {
  algorithm: 'ES256',
  expiresIn: 60, // 1 minute for DPoP proofs
  clockTolerance: 60,
  maxAge: 300,
  enableFingerprinting: true,
  issuer: 'dpop-auth',
  audience: 'dpop-auth',
};

/**
 * Create a DPoP proof JWT
 */
export async function createDPoPProof(
  httpMethod: string,
  httpUri: string,
  privateKey: KeyLike,
  publicKeyJwk: any,
  options: {
    accessToken?: string;
    fingerprint?: string;
    algorithm?: DPoPAlgorithm;
  } = {}
): Promise<string> {
  const { algorithm = 'ES256', accessToken, fingerprint } = options;
  const now = Math.floor(Date.now() / 1000);
  const jti = generateJTI();

  // Build DPoP payload
  const payload: DPoPPayload = {
    htm: httpMethod.toUpperCase(),
    htu: httpUri,
    iat: now,
    jti,
  };

  // Add access token hash if provided
  if (accessToken) {
    payload.ath = createAccessTokenHash(accessToken);
  }

  // Add fingerprint hash if provided
  if (fingerprint) {
    payload.fph = fingerprint;
  }

  // Create and sign DPoP JWT
  const dpopJwt = await new SignJWT(payload)
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: algorithm,
      jwk: publicKeyJwk,
    })
    .sign(privateKey);

  return dpopJwt;
}

/**
 * Verify a DPoP proof JWT
 */
export async function verifyDPoPProof(
  dpopProof: string,
  httpMethod: string,
  httpUri: string,
  options: Partial<DPoPConfig> & {
    accessToken?: string;
    expectedFingerprint?: string | undefined;
    replayStore?: ReplayStore;
  } = {}
): Promise<DPoPVerificationResult> {
  const config = { ...DEFAULT_CONFIG, ...options };

  try {
    // Decode header to get public key
    const header = decodeProtectedHeader(dpopProof);

    // Validate header
    if (header.typ !== 'dpop+jwt') {
      return { valid: false, error: 'Invalid JWT type, expected dpop+jwt' };
    }

    if (!header.jwk) {
      return { valid: false, error: 'Missing public key in JWT header' };
    }

    // Import public key from header
    const publicKey = await importJWK(header.jwk, header.alg as string);
    const thumbprint = await getKeyThumbprint(header.jwk);

    // Verify JWT signature
    const { payload } = await jwtVerify(dpopProof, publicKey, {
      clockTolerance: config.clockTolerance,
    });

    const dpopPayload = payload as DPoPPayload;

    // Validate required claims
    if (!dpopPayload.htm || !dpopPayload.htu || !dpopPayload.iat || !dpopPayload.jti) {
      return { valid: false, error: 'Missing required DPoP claims' };
    }

    // Validate HTTP method and URI
    if (dpopPayload.htm !== httpMethod.toUpperCase()) {
      return {
        valid: false,
        error: `HTTP method mismatch: expected ${httpMethod.toUpperCase()}, got ${dpopPayload.htm}`
      };
    }

    if (dpopPayload.htu !== httpUri) {
      return {
        valid: false,
        error: `HTTP URI mismatch: expected ${httpUri}, got ${dpopPayload.htu}`
      };
    }

    // Validate timestamp
    const timestampValidation = validateTimestamp(dpopPayload.iat, config.clockTolerance);
    if (!timestampValidation.valid) {
      return { valid: false, error: timestampValidation.error || 'Invalid timestamp' };
    }

    // Check for replay attacks
    if (options.replayStore) {
      const isReplayed = await options.replayStore.has(dpopPayload.jti);
      if (isReplayed) {
        return { valid: false, error: 'DPoP proof replay detected' };
      }

      // Store JTI to prevent replay
      const expiresAt = (dpopPayload.iat + config.maxAge) * 1000;
      await options.replayStore.set(dpopPayload.jti, expiresAt);
    }

    // Validate access token hash if provided
    if (options.accessToken) {
      const expectedAth = createAccessTokenHash(options.accessToken);
      if (dpopPayload.ath !== expectedAth) {
        return {
          valid: false,
          error: 'Access token hash mismatch'
        };
      }
    }

    // Validate fingerprint if provided
    if (config.enableFingerprinting && options.expectedFingerprint) {
      if (dpopPayload.fph !== options.expectedFingerprint) {
        return {
          valid: false,
          error: 'Fingerprint mismatch'
        };
      }
    }

    return {
      valid: true,
      payload: dpopPayload,
      thumbprint,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'DPoP verification failed',
    };
  }
}

/**
 * Extract public key JWK from DPoP proof header
 */
export function extractPublicKeyFromDPoP(dpopProof: string): any | null {
  try {
    const header = decodeProtectedHeader(dpopProof);
    return header.jwk || null;
  } catch {
    return null;
  }
}

/**
 * Extract thumbprint from DPoP proof
 */
export async function extractThumbprintFromDPoP(dpopProof: string): Promise<string | null> {
  try {
    const publicKeyJwk = extractPublicKeyFromDPoP(dpopProof);
    if (!publicKeyJwk) return null;

    return await getKeyThumbprint(publicKeyJwk);
  } catch {
    return null;
  }
}

/**
 * Validate DPoP proof format without full verification
 */
export function validateDPoPFormat(dpopProof: string): { valid: boolean; error?: string } {
  try {
    const header = decodeProtectedHeader(dpopProof);
    const payload = decodeJwt(dpopProof);

    // Check header
    if (header.typ !== 'dpop+jwt') {
      return { valid: false, error: 'Invalid JWT type' };
    }

    if (!header.jwk) {
      return { valid: false, error: 'Missing public key in header' };
    }

    if (!header.alg || !['ES256', 'RS256'].includes(header.alg)) {
      return { valid: false, error: 'Invalid or missing algorithm' };
    }

    // Check payload
    const requiredClaims = ['htm', 'htu', 'iat', 'jti'];
    for (const claim of requiredClaims) {
      if (!(claim in payload)) {
        return { valid: false, error: `Missing required claim: ${claim}` };
      }
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid DPoP format'
    };
  }
}

/**
 * Create a simple in-memory replay store for development
 */
export class MemoryReplayStore implements ReplayStore {
  private store = new Map<string, number>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(cleanupIntervalMs: number = 60000) {
    // Auto-cleanup every minute by default
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref(); // Don't hold the process open
      }
    }
  }

  async set(jti: string, expiresAt: number): Promise<void> {
    this.store.set(jti, expiresAt);
  }

  async has(jti: string): Promise<boolean> {
    const expiresAt = this.store.get(jti);
    if (!expiresAt) return false;

    // Check if expired
    if (Date.now() > expiresAt) {
      this.store.delete(jti);
      return false;
    }

    return true;
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [jti, expiresAt] of this.store.entries()) {
      if (now > expiresAt) {
        this.store.delete(jti);
      }
    }
  }

  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
