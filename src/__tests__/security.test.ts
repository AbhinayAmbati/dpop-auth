import {
    secureCompare,
    validateSecretStrength,
    sanitizeForLogging,
    maskSensitiveData,
    createHmacHash,
    IPUtils,
} from '../core/security';

describe('Security Utilities', () => {
    describe('secureCompare', () => {
        it('should return true for identical strings', () => {
            expect(secureCompare('my-secret-token', 'my-secret-token')).toBe(true);
        });

        it('should return false for different strings of equal length', () => {
            expect(secureCompare('my-secret-token-1', 'my-secret-token-2')).toBe(false);
        });

        it('should return false for strings of unequal length without timing leak', () => {
            expect(secureCompare('short', 'longer-string-value')).toBe(false);
            expect(secureCompare('', 'non-empty')).toBe(false);
            expect(secureCompare('', '')).toBe(true);
        });
    });

    describe('validateSecretStrength', () => {
        it('should pass strong random secret', () => {
            const strongSecret = 'A!9kL#4pZ$7wQ*2mN@8vX%1yC^6bT&3h';
            const result = validateSecretStrength(strongSecret);
            expect(result.valid).toBe(true);
            expect(result.score).toBeGreaterThanOrEqual(80);
            expect(result.issues).toHaveLength(0);
        });

        it('should fail short secret', () => {
            const shortSecret = 'short1!';
            const result = validateSecretStrength(shortSecret);
            expect(result.valid).toBe(false);
            expect(result.issues.some(issue => issue.includes('32 characters'))).toBe(true);
        });

        it('should flag low-entropy repetitive secret (Bug #10 verification)', () => {
            const repetitiveSecret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1!';
            const result = validateSecretStrength(repetitiveSecret);
            expect(result.issues.some(issue => issue.includes('Entropy is low'))).toBe(true);
        });
    });

    describe('sanitizeForLogging and maskSensitiveData', () => {
        it('should strip newlines and control characters from input', () => {
            const maliciousInput = 'admin\nUser-Role: superadmin\r\t';
            const sanitized = sanitizeForLogging(maliciousInput);
            expect(sanitized).not.toContain('\n');
            expect(sanitized).not.toContain('\r');
            expect(sanitized).not.toContain('\t');
        });

        it('should mask sensitive strings preserving only edges', () => {
            const apiKey = 'sk_live_abcdefghijklmn';
            const masked = maskSensitiveData(apiKey, 4);
            expect(masked.startsWith('sk_l')).toBe(true);
            expect(masked.endsWith('klmn')).toBe(true);
            expect(masked).toContain('*');
        });

        it('should mask completely if string is too short', () => {
            expect(maskSensitiveData('abc', 4)).toBe('***');
        });
    });

    describe('createHmacHash', () => {
        it('should produce consistent HMAC hashes with top-level import', () => {
            const h1 = createHmacHash('data', 'secret-key');
            const h2 = createHmacHash('data', 'secret-key');
            const h3 = createHmacHash('different-data', 'secret-key');

            expect(h1).toBe(h2);
            expect(h1).not.toBe(h3);
        });
    });

    describe('IPUtils', () => {
        it('should validate IP addresses', () => {
            expect(IPUtils.isValid('192.168.1.1')).toBe(true);
            expect(IPUtils.isValid('256.0.0.1')).toBe(false);
            expect(IPUtils.isValid('not-an-ip')).toBe(false);
        });

        it('should recognize private IP addresses', () => {
            expect(IPUtils.isPrivate('192.168.1.1')).toBe(true);
            expect(IPUtils.isPrivate('10.0.0.1')).toBe(true);
            expect(IPUtils.isPrivate('8.8.8.8')).toBe(false);
        });
    });
});
