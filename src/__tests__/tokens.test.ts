import {
    createAccessToken,
    createRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    extractThumbprintFromToken,
    isTokenExpired,
} from '../core/tokens';
import { generateDPoPKeyPair } from '../core/crypto';

describe('Token Functions', () => {
    let keyPair: Awaited<ReturnType<typeof generateDPoPKeyPair>>;
    const secret = 'test-secret-key-for-testing-purposes-32chars';

    beforeAll(async () => {
        keyPair = await generateDPoPKeyPair();
    });

    describe('createAccessToken', () => {
        it('should create a valid access token', async () => {
            const result = await createAccessToken('user123', keyPair.publicKeyJwk, secret);

            expect(result.token).toBeDefined();
            expect(typeof result.token).toBe('string');
            expect(result.expiresAt).toBeGreaterThan(Date.now());
            expect(result.jti).toBeDefined();
        });

        it('should include custom claims', async () => {
            const result = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                customClaims: { role: 'admin', department: 'engineering' },
            });

            const verification = await verifyAccessToken(result.token, secret);
            expect(verification.valid).toBe(true);
            expect((verification.payload as any)?.['role']).toBe('admin');
            expect((verification.payload as any)?.['department']).toBe('engineering');
        });

        it('should include fingerprint when enabled', async () => {
            const result = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                enableFingerprinting: true,
                fingerprint: 'test-fingerprint-hash',
            });

            const verification = await verifyAccessToken(result.token, secret);
            expect(verification.valid).toBe(true);
            expect(verification.payload?.fph).toBe('test-fingerprint-hash');
        });

        it('should include device key thumbprint (cnf.jkt)', async () => {
            const result = await createAccessToken('user123', keyPair.publicKeyJwk, secret);

            const verification = await verifyAccessToken(result.token, secret);
            expect(verification.valid).toBe(true);
            expect(verification.payload?.cnf?.jkt).toBe(keyPair.thumbprint);
        });
    });

    describe('createRefreshToken', () => {
        it('should create a valid refresh token', async () => {
            const result = await createRefreshToken('user123', keyPair.publicKeyJwk, secret);

            expect(result.token).toBeDefined();
            expect(result.expiresAt).toBeGreaterThan(Date.now());
            // Refresh token should expire in 7 days by default
            const expiresInSeconds = (result.expiresAt - Date.now()) / 1000;
            expect(expiresInSeconds).toBeGreaterThan(6 * 24 * 60 * 60); // > 6 days
        });

        it('should have typ: refresh in payload', async () => {
            const result = await createRefreshToken('user123', keyPair.publicKeyJwk, secret);

            const verification = await verifyRefreshToken(result.token, secret);
            expect(verification.valid).toBe(true);
            expect((verification.payload as any)?.typ).toBe('refresh');
        });
    });

    describe('verifyAccessToken', () => {
        it('should verify a valid token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);
            const result = await verifyAccessToken(token.token, secret);

            expect(result.valid).toBe(true);
            expect(result.payload?.sub).toBe('user123');
        });

        it('should reject token with invalid secret', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);
            const result = await verifyAccessToken(token.token, 'wrong-secret-that-is-long-enough');

            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        it('should reject expired token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                expiresIn: -1, // Already expired
            });
            const result = await verifyAccessToken(token.token, secret);

            expect(result.valid).toBe(false);
        });
    });

    describe('verifyRefreshToken', () => {
        it('should verify a valid refresh token', async () => {
            const token = await createRefreshToken('user123', keyPair.publicKeyJwk, secret);
            const result = await verifyRefreshToken(token.token, secret);

            expect(result.valid).toBe(true);
            expect(result.payload?.sub).toBe('user123');
            expect((result.payload as any)?.typ).toBe('refresh');
        });

        it('should reject access token as refresh token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);
            const result = await verifyRefreshToken(token.token, secret);

            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });
    });

    describe('extractThumbprintFromToken', () => {
        it('should extract thumbprint from valid token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);
            const thumbprint = extractThumbprintFromToken(token.token);

            expect(thumbprint).toBe(keyPair.thumbprint);
        });

        it('should return null for invalid token', () => {
            const thumbprint = extractThumbprintFromToken('invalid-token');
            expect(thumbprint).toBeNull();
        });
    });

    describe('isTokenExpired', () => {
        it('should return false for valid token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);
            const expired = isTokenExpired(token.token);

            expect(expired).toBe(false);
        });

        it('should return true for expired token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                expiresIn: -1,
            });
            const expired = isTokenExpired(token.token);

            expect(expired).toBe(true);
        });

        it('should return true for invalid token', () => {
            const expired = isTokenExpired('invalid-token');
            expect(expired).toBe(true);
        });
    });
});
