import {
    introspectToken,
    MemoryRevocationStore,
    TokenRotationManager,
    validateTokenStructure,
    getTokenLifetime,
} from '../core/token-utils';
import { createAccessToken, createRefreshToken } from '../core/tokens';
import { generateDPoPKeyPair } from '../core/crypto';

describe('Token Utilities', () => {
    let keyPair: Awaited<ReturnType<typeof generateDPoPKeyPair>>;
    const secret = 'test-secret-key-for-testing-purposes-32chars';

    beforeAll(async () => {
        keyPair = await generateDPoPKeyPair();
    });

    describe('introspectToken', () => {
        it('should introspect a valid access token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                customClaims: { role: 'admin' },
            });

            const result = introspectToken(token.token);

            expect(result.active).toBe(true);
            expect(result.tokenType).toBe('access');
            expect(result.subject).toBe('user123');
            expect(result.deviceThumbprint).toBe(keyPair.thumbprint);
        });

        it('should introspect a valid refresh token', async () => {
            const token = await createRefreshToken('user456', keyPair.publicKeyJwk, secret);

            const result = introspectToken(token.token);

            expect(result.active).toBe(true);
            expect(result.tokenType).toBe('refresh');
            expect(result.subject).toBe('user456');
        });

        it('should mark expired token as inactive', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                expiresIn: -1,
            });

            const result = introspectToken(token.token);

            expect(result.active).toBe(false);
        });

        it('should return error for invalid token', () => {
            const result = introspectToken('invalid-token');

            expect(result.active).toBe(false);
            expect(result.error).toBeDefined();
        });
    });

    describe('MemoryRevocationStore', () => {
        it('should revoke and check tokens', async () => {
            const store = new MemoryRevocationStore();

            // Initially not revoked
            expect(await store.isRevoked('jti123')).toBe(false);

            // Revoke the token
            const futureExpiration = Math.floor(Date.now() / 1000) + 3600;
            await store.revoke('jti123', futureExpiration);

            // Now should be revoked
            expect(await store.isRevoked('jti123')).toBe(true);

            store.stop();
        });

        it('should auto-expire revoked tokens', async () => {
            const store = new MemoryRevocationStore();

            // Revoke with past expiration
            const pastExpiration = Math.floor(Date.now() / 1000) - 1;
            await store.revoke('jti-expired', pastExpiration);

            // Should not be considered revoked (expired)
            expect(await store.isRevoked('jti-expired')).toBe(false);

            store.stop();
        });
    });

    describe('TokenRotationManager', () => {
        it('should track token rotations', () => {
            const manager = new TokenRotationManager({ gracePeriodMs: 1000 });

            manager.recordRotation('old-jti', 'new-jti');

            // Within grace period
            const newJti = manager.checkGracePeriod('old-jti');
            expect(newJti).toBe('new-jti');

            manager.stop();
        });

        it('should detect token reuse after grace period', async () => {
            const manager = new TokenRotationManager({ gracePeriodMs: 50 });

            manager.recordRotation('old-jti', 'new-jti');

            // Wait for grace period to expire
            await new Promise(resolve => setTimeout(resolve, 60));

            const isReuse = manager.detectReuse('old-jti');
            expect(isReuse).toBe(true);

            manager.stop();
        });
    });

    describe('validateTokenStructure', () => {
        it('should validate a properly structured token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret);

            const result = validateTokenStructure(token.token);

            expect(result.valid).toBe(true);
            expect(result.parts).toBeDefined();
            expect(result.parts?.payload).toBeDefined();
        });

        it('should reject invalid token structure', () => {
            const result = validateTokenStructure('not.valid');

            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });
    });

    describe('getTokenLifetime', () => {
        it('should return remaining lifetime for valid token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                expiresIn: 300,
            });

            const result = getTokenLifetime(token.token);

            expect(result.valid).toBe(true);
            expect(result.isExpired).toBe(false);
            expect(result.remainingSeconds).toBeGreaterThan(0);
            expect(result.remainingSeconds).toBeLessThanOrEqual(300);
        });

        it('should indicate expired token', async () => {
            const token = await createAccessToken('user123', keyPair.publicKeyJwk, secret, {
                expiresIn: -1,
            });

            const result = getTokenLifetime(token.token);

            expect(result.valid).toBe(true);
            expect(result.isExpired).toBe(true);
            expect(result.remainingSeconds).toBe(0);
        });
    });
});
