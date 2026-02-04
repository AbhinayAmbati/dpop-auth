import {
    createDPoPProof,
    verifyDPoPProof,
    extractPublicKeyFromDPoP,
    extractThumbprintFromDPoP,
    validateDPoPFormat,
    MemoryReplayStore,
} from '../core/dpop';
import { generateDPoPKeyPair } from '../core/crypto';

describe('DPoP Functions', () => {
    let keyPair: Awaited<ReturnType<typeof generateDPoPKeyPair>>;

    beforeAll(async () => {
        keyPair = await generateDPoPKeyPair();
    });

    describe('createDPoPProof', () => {
        it('should create a valid DPoP proof', async () => {
            const proof = await createDPoPProof(
                'POST',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            expect(typeof proof).toBe('string');
            expect(proof.split('.')).toHaveLength(3);
        });

        it('should include access token hash when provided', async () => {
            const accessToken = 'test-access-token';
            const proof = await createDPoPProof(
                'POST',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk,
                { accessToken }
            );

            const verification = await verifyDPoPProof(
                proof,
                'POST',
                'https://api.example.com/data',
                { accessToken }
            );

            expect(verification.valid).toBe(true);
        });

        it('should include fingerprint when provided', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk,
                { fingerprint: 'test-fingerprint' }
            );

            const verification = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/data',
                { expectedFingerprint: 'test-fingerprint' }
            );

            expect(verification.valid).toBe(true);
        });
    });

    describe('verifyDPoPProof', () => {
        it('should verify a valid DPoP proof', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const result = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/data'
            );

            expect(result.valid).toBe(true);
            expect(result.thumbprint).toBe(keyPair.thumbprint);
        });

        it('should reject proof with method mismatch', async () => {
            const proof = await createDPoPProof(
                'POST',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const result = await verifyDPoPProof(
                proof,
                'GET', // Different method
                'https://api.example.com/data'
            );

            expect(result.valid).toBe(false);
            expect(result.error).toContain('method mismatch');
        });

        it('should reject proof with URI mismatch', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const result = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/other' // Different URI
            );

            expect(result.valid).toBe(false);
            expect(result.error).toContain('URI mismatch');
        });

        it('should reject proof with access token hash mismatch', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk,
                { accessToken: 'token1' }
            );

            const result = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/data',
                { accessToken: 'token2' } // Different token
            );

            expect(result.valid).toBe(false);
            expect(result.error).toContain('hash mismatch');
        });
    });

    describe('MemoryReplayStore', () => {
        it('should detect replay attacks', async () => {
            const store = new MemoryReplayStore();

            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            // First use should succeed
            const result1 = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/data',
                { replayStore: store }
            );
            expect(result1.valid).toBe(true);

            // Second use should fail
            const result2 = await verifyDPoPProof(
                proof,
                'GET',
                'https://api.example.com/data',
                { replayStore: store }
            );
            expect(result2.valid).toBe(false);
            expect(result2.error).toContain('replay');

            store.stopCleanup();
        });
    });

    describe('extractPublicKeyFromDPoP', () => {
        it('should extract public key from valid DPoP proof', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const publicKey = extractPublicKeyFromDPoP(proof);

            expect(publicKey).toBeDefined();
            expect(publicKey.kty).toBe(keyPair.publicKeyJwk.kty);
        });

        it('should return null for invalid proof', () => {
            const publicKey = extractPublicKeyFromDPoP('invalid-proof');
            expect(publicKey).toBeNull();
        });
    });

    describe('extractThumbprintFromDPoP', () => {
        it('should extract thumbprint from valid DPoP proof', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const thumbprint = await extractThumbprintFromDPoP(proof);

            expect(thumbprint).toBe(keyPair.thumbprint);
        });
    });

    describe('validateDPoPFormat', () => {
        it('should validate a correct DPoP format', async () => {
            const proof = await createDPoPProof(
                'GET',
                'https://api.example.com/data',
                keyPair.privateKey,
                keyPair.publicKeyJwk
            );

            const result = validateDPoPFormat(proof);

            expect(result.valid).toBe(true);
        });

        it('should reject invalid format', () => {
            const result = validateDPoPFormat('not-a-jwt');
            expect(result.valid).toBe(false);
        });
    });
});
