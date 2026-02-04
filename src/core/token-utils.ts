/**
 * Token utilities for advanced token management
 * Includes revocation, introspection, and rotation
 */

import { decodeJwt, decodeProtectedHeader } from 'jose';

/**
 * Token introspection result
 */
export interface TokenIntrospectionResult {
    active: boolean;
    tokenType?: 'access' | 'refresh';
    subject?: string;
    issuedAt?: number;
    expiresAt?: number;
    jti?: string;
    issuer?: string;
    audience?: string;
    deviceThumbprint?: string;
    fingerprint?: string;
    claims?: Record<string, any>;
    error?: string;
}

/**
 * Introspect a token without full verification
 * Useful for debugging and token management
 */
export function introspectToken(token: string): TokenIntrospectionResult {
    try {
        // Decode header for validation (not used directly but ensures valid JWT format)
        decodeProtectedHeader(token);
        const payload = decodeJwt(token) as any;
        const now = Math.floor(Date.now() / 1000);

        // Check if expired
        const isExpired = payload.exp && payload.exp < now;

        // Determine token type
        const tokenType = payload.typ === 'refresh' ? 'refresh' : 'access';

        // Extract known claims
        const { sub, iat, exp, jti, iss, aud, cnf, fph, ...customClaims } = payload;

        return {
            active: !isExpired,
            tokenType,
            subject: sub,
            issuedAt: iat,
            expiresAt: exp,
            jti,
            issuer: iss,
            audience: aud,
            deviceThumbprint: cnf?.jkt,
            fingerprint: fph,
            claims: Object.keys(customClaims).length > 0 ? customClaims : undefined,
        };
    } catch (error) {
        return {
            active: false,
            error: error instanceof Error ? error.message : 'Failed to introspect token',
        };
    }
}

/**
 * Token revocation interface
 */
export interface RevocationStore {
    revoke(jti: string, expiresAt: number): Promise<void>;
    isRevoked(jti: string): Promise<boolean>;
    revokeAllForUser?(userId: string): Promise<void>;
}

/**
 * Simple in-memory revocation store
 */
export class MemoryRevocationStore implements RevocationStore {
    private store: Map<string, number>;
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor(cleanupIntervalMs: number = 60000) {
        this.store = new Map();

        if (typeof setInterval !== 'undefined') {
            this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
            if (this.cleanupInterval.unref) {
                this.cleanupInterval.unref();
            }
        }
    }

    async revoke(jti: string, expiresAt: number): Promise<void> {
        this.store.set(jti, expiresAt);
    }

    async isRevoked(jti: string): Promise<boolean> {
        const expiresAt = this.store.get(jti);
        if (!expiresAt) return false;

        // If the natural expiration has passed, remove from store
        if (Date.now() > expiresAt * 1000) {
            this.store.delete(jti);
            return false;
        }

        return true;
    }

    cleanup(): void {
        const now = Date.now();
        for (const [jti, expiresAt] of this.store.entries()) {
            if (now > expiresAt * 1000) {
                this.store.delete(jti);
            }
        }
    }

    stop(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
    }

    get size(): number {
        return this.store.size;
    }
}

/**
 * Token rotation manager
 * Helps implement secure token rotation patterns
 */
export class TokenRotationManager {
    private rotatedTokens: Map<string, { newJti: string; rotatedAt: number }>;
    private gracePeriodMs: number;
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor(options: { gracePeriodMs?: number; cleanupIntervalMs?: number } = {}) {
        this.rotatedTokens = new Map();
        this.gracePeriodMs = options.gracePeriodMs || 30000; // 30 seconds grace period

        if (typeof setInterval !== 'undefined') {
            const cleanupIntervalMs = options.cleanupIntervalMs || 60000;
            this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
            if (this.cleanupInterval.unref) {
                this.cleanupInterval.unref();
            }
        }
    }

    /**
     * Record a token rotation
     */
    recordRotation(oldJti: string, newJti: string): void {
        this.rotatedTokens.set(oldJti, {
            newJti,
            rotatedAt: Date.now(),
        });
    }

    /**
     * Check if an old token is within the grace period
     * Returns the new JTI if within grace period, null otherwise
     */
    checkGracePeriod(oldJti: string): string | null {
        const rotation = this.rotatedTokens.get(oldJti);
        if (!rotation) return null;

        const elapsed = Date.now() - rotation.rotatedAt;
        if (elapsed > this.gracePeriodMs) {
            this.rotatedTokens.delete(oldJti);
            return null;
        }

        return rotation.newJti;
    }

    /**
     * Detect token reuse attack (old rotated token used outside grace period)
     */
    detectReuse(jti: string): boolean {
        const rotation = this.rotatedTokens.get(jti);
        if (!rotation) return false;

        const elapsed = Date.now() - rotation.rotatedAt;
        return elapsed > this.gracePeriodMs;
    }

    cleanup(): void {
        const now = Date.now();
        const maxAge = this.gracePeriodMs * 2; // Keep for 2x grace period for reuse detection

        for (const [jti, rotation] of this.rotatedTokens.entries()) {
            if (now - rotation.rotatedAt > maxAge) {
                this.rotatedTokens.delete(jti);
            }
        }
    }

    stop(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
    }
}

/**
 * Decode and validate token structure
 */
export function validateTokenStructure(token: string): {
    valid: boolean;
    error?: string;
    parts?: {
        header: any;
        payload: any;
    };
} {
    try {
        // Check basic JWT structure
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid JWT structure: expected 3 parts' };
        }

        const header = decodeProtectedHeader(token);
        const payload = decodeJwt(token);

        // Validate algorithm
        if (!header.alg || !['HS256', 'RS256', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'].includes(header.alg)) {
            return { valid: false, error: `Invalid or unsupported algorithm: ${header.alg}` };
        }

        // Validate required claims
        if (!payload.sub) {
            return { valid: false, error: 'Missing subject claim (sub)' };
        }

        if (!payload.exp) {
            return { valid: false, error: 'Missing expiration claim (exp)' };
        }

        if (!payload.iat) {
            return { valid: false, error: 'Missing issued-at claim (iat)' };
        }

        return {
            valid: true,
            parts: { header, payload },
        };
    } catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Invalid token',
        };
    }
}

/**
 * Calculate remaining token lifetime in seconds
 */
export function getTokenLifetime(token: string): {
    valid: boolean;
    remainingSeconds?: number;
    isExpired?: boolean;
    error?: string;
} {
    try {
        const payload = decodeJwt(token);
        const now = Math.floor(Date.now() / 1000);

        if (!payload.exp) {
            return { valid: false, error: 'Token has no expiration' };
        }

        const remaining = payload.exp - now;
        return {
            valid: true,
            remainingSeconds: Math.max(0, remaining),
            isExpired: remaining <= 0,
        };
    } catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : 'Invalid token',
        };
    }
}
