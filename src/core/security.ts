/**
 * Security utilities and hardening functions
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function secureCompare(a: string, b: string): boolean {
    try {
        // Hash both inputs to fixed-length buffers to prevent
        // length-based timing side-channel attacks
        const hashA = createHash('sha256').update(a, 'utf8').digest();
        const hashB = createHash('sha256').update(b, 'utf8').digest();

        return timingSafeEqual(hashA, hashB);
    } catch {
        return false;
    }
}

/**
 * Constant-time buffer comparison
 */
export function secureCompareBuffers(a: Buffer, b: Buffer): boolean {
    try {
        if (a.length !== b.length) {
            // Maintain constant time by comparing a to itself
            timingSafeEqual(a, a);
            return false;
        }
        return timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

/**
 * Generate cryptographically secure random bytes
 */
export function generateSecureBytes(length: number = 32): Buffer {
    return randomBytes(length);
}

/**
 * Generate a secure random string (URL-safe base64)
 */
export function generateSecureString(length: number = 32): string {
    const bytes = randomBytes(Math.ceil(length * 0.75));
    return bytes.toString('base64url').slice(0, length);
}

/**
 * Create a secure hash using HMAC
 */
export function createHmacHash(data: string, secret: string, algorithm: string = 'sha256'): string {
    return createHmac(algorithm, secret).update(data).digest('base64url');
}

/**
 * Validate secret strength
 */
export function validateSecretStrength(secret: string): {
    valid: boolean;
    score: number;
    issues: string[];
} {
    const issues: string[] = [];
    let score = 0;

    // Minimum length check
    if (secret.length < 32) {
        issues.push('Secret should be at least 32 characters');
    } else {
        score += 25;
    }

    // Character diversity
    if (!/[a-z]/.test(secret)) {
        issues.push('Secret should contain lowercase letters');
    } else {
        score += 15;
    }

    if (!/[A-Z]/.test(secret)) {
        issues.push('Secret should contain uppercase letters');
    } else {
        score += 15;
    }

    if (!/[0-9]/.test(secret)) {
        issues.push('Secret should contain numbers');
    } else {
        score += 15;
    }

    if (!/[^a-zA-Z0-9]/.test(secret)) {
        issues.push('Secret should contain special characters');
    } else {
        score += 15;
    }

    // Entropy estimation using Shannon entropy (avoids Math.pow overflow on long secrets)
    const charFrequencies = new Map<string, number>();
    for (const char of secret) {
        charFrequencies.set(char, (charFrequencies.get(char) || 0) + 1);
    }
    let shannonEntropy = 0;
    for (const count of charFrequencies.values()) {
        const p = count / secret.length;
        shannonEntropy -= p * Math.log2(p);
    }
    const entropy = shannonEntropy * secret.length;

    if (entropy < 128) {
        issues.push(`Entropy is low (${Math.floor(entropy)} bits), aim for at least 128 bits`);
    } else {
        score += 15;
    }

    return {
        valid: issues.length === 0,
        score,
        issues,
    };
}

/**
 * Sanitize user input for logging (prevent log injection)
 */
export function sanitizeForLogging(input: string, maxLength: number = 100): string {
    return input
        .replace(/[\n\r\t]/g, ' ')
        .replace(/[^\x20-\x7E]/g, '')
        .slice(0, maxLength);
}

/**
 * Mask sensitive data for logging
 */
export function maskSensitiveData(data: string, visibleChars: number = 4): string {
    if (data.length <= visibleChars * 2) {
        return '*'.repeat(data.length);
    }

    const start = data.slice(0, visibleChars);
    const end = data.slice(-visibleChars);
    const middle = '*'.repeat(Math.min(data.length - visibleChars * 2, 10));

    return `${start}${middle}${end}`;
}

/**
 * Check for common security issues in JWK
 */
export function validateJwkSecurity(jwk: any): {
    valid: boolean;
    issues: string[];
} {
    const issues: string[] = [];

    // Check for private key exposure
    if (jwk.d || jwk.p || jwk.q || jwk.dp || jwk.dq || jwk.qi) {
        issues.push('JWK contains private key components - ensure this is intentional');
    }

    // Check key type
    if (!['EC', 'RSA', 'OKP'].includes(jwk.kty)) {
        issues.push(`Unsupported key type: ${jwk.kty}`);
    }

    // EC key checks
    if (jwk.kty === 'EC') {
        if (!['P-256', 'P-384', 'P-521'].includes(jwk.crv)) {
            issues.push(`Weak or unsupported curve: ${jwk.crv}`);
        }
    }

    // RSA key checks
    if (jwk.kty === 'RSA') {
        // Check key size through modulus length
        if (jwk.n) {
            const modulusBytes = Buffer.from(jwk.n, 'base64url');
            const keySizeBits = modulusBytes.length * 8;
            if (keySizeBits < 2048) {
                issues.push(`RSA key size (${keySizeBits} bits) is below recommended minimum of 2048 bits`);
            }
        }
    }

    return {
        valid: issues.length === 0,
        issues,
    };
}

/**
 * IP address validation utilities
 */
export const IPUtils = {
    /**
     * Check if IP is private
     */
    isPrivate(ip: string): boolean {
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./,
            /^::1$/,
            /^fc00:/i,
            /^fe80:/i,
        ];
        return privateRanges.some(range => range.test(ip));
    },

    /**
     * Extract real IP from proxy headers
     */
    getRealIP(req: any, trustProxy: boolean = false): string {
        if (trustProxy) {
            const forwarded = req.get?.('x-forwarded-for');
            if (forwarded) {
                const ips = forwarded.split(',').map((ip: string) => ip.trim());
                return ips[0] || req.ip || 'unknown';
            }

            const realIP = req.get?.('x-real-ip');
            if (realIP) {
                return realIP;
            }
        }

        return req.ip || req.connection?.remoteAddress || 'unknown';
    },

    /**
     * Validate IP address format
     */
    isValid(ip: string): boolean {
        const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (ipv4Match) {
            return ipv4Match.slice(1).every(octet => Number(octet) >= 0 && Number(octet) <= 255);
        }
        const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;

        return ipv6.test(ip);
    },
};

/**
 * Request signing for additional integrity verification
 */
export function createRequestSignature(
    method: string,
    url: string,
    timestamp: number,
    secret: string,
    body?: string
): string {
    const message = [
        method.toUpperCase(),
        url,
        timestamp.toString(),
        body ? createHash('sha256').update(body).digest('base64url') : '',
    ].join('\n');

    return createHmacHash(message, secret);
}

/**
 * Verify request signature
 */
export function verifyRequestSignature(
    signature: string,
    method: string,
    url: string,
    timestamp: number,
    secret: string,
    body?: string,
    maxAgeSeconds: number = 300
): { valid: boolean; error?: string } {
    // Check timestamp
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > maxAgeSeconds) {
        return { valid: false, error: 'Request signature expired' };
    }

    const expectedSignature = createRequestSignature(method, url, timestamp, secret, body);

    if (!secureCompare(signature, expectedSignature)) {
        return { valid: false, error: 'Invalid request signature' };
    }

    return { valid: true };
}
