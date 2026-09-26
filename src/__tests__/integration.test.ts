import DPoPAuth, {
    MemoryRevocationStore,
    MemoryReplayStore,
    generateDPoPKeyPair,
    createDPoPProof,
    verifyDPoPProof,
} from '../index';

describe('Integration: Full DPoP Authentication Flow', () => {
    const secret = 'integration-test-secret-at-least-32-chars-long';
    let auth: DPoPAuth;
    let revocationStore: MemoryRevocationStore;
    let replayStore: MemoryReplayStore;

    beforeEach(() => {
        revocationStore = new MemoryRevocationStore();
        replayStore = new MemoryReplayStore();
        auth = new DPoPAuth(secret, {
            revocationStore,
            replayStore,
        });
    });

    afterEach(() => {
        auth.destroy();
    });

    it('completes the entire client-server authentication lifecycle', async () => {
        // 1. Client generates key pair
        const clientKeyPair = await generateDPoPKeyPair({ algorithm: 'ES256' });
        expect(clientKeyPair.publicKeyJwk).toBeDefined();
        expect(clientKeyPair.thumbprint).toBeDefined();

        // 2. Server creates tokens bound to client's key
        const flow = await auth.createAuthFlow(
            'user_999',
            clientKeyPair.publicKeyJwk,
            'device-fingerprint-123'
        );
        expect(flow.accessToken).toBeDefined();
        expect(flow.refreshToken).toBeDefined();
        expect(flow.thumbprint).toBe(clientKeyPair.thumbprint);

        // 3. Client creates DPoP proof for an API request
        const httpMethod = 'POST';
        const httpUri = 'https://api.example.com/transactions';
        const proof = await createDPoPProof(
            httpMethod,
            httpUri,
            clientKeyPair.privateKey,
            clientKeyPair.publicKeyJwk,
            {
                accessToken: flow.accessToken.token,
                fingerprint: 'device-fingerprint-123',
            }
        );

        // 4. Server verifies the DPoP proof
        const proofVerification = await verifyDPoPProof(
            proof,
            httpMethod,
            httpUri,
            {
                accessToken: flow.accessToken.token,
                expectedFingerprint: 'device-fingerprint-123',
                replayStore,
            }
        );
        expect(proofVerification.valid).toBe(true);
        expect(proofVerification.thumbprint).toBe(clientKeyPair.thumbprint);

        // 5. Server verifies token status
        const tokenCheck = await auth.verifyToken(flow.accessToken.token);
        expect(tokenCheck.valid).toBe(true);

        // 6. Server rotates the tokens using refresh token
        const newAccessToken = await auth.refreshAccessToken(
            flow.refreshToken.token,
            clientKeyPair.publicKeyJwk,
            'device-fingerprint-123'
        );
        expect(newAccessToken.token).toBeDefined();

        // 7. Server revokes the old access token
        const revoked = await auth.revokeToken(flow.accessToken.token);
        expect(revoked).toBe(true);

        // 8. Verify the token is now rejected upon verification
        const revokedCheck = await auth.verifyToken(flow.accessToken.token);
        expect(revokedCheck.valid).toBe(false);
        expect(revokedCheck.error).toContain('revoked');
    });

    it('rejects replayed DPoP proofs with replay store', async () => {
        const clientKeyPair = await generateDPoPKeyPair();
        const httpMethod = 'GET';
        const httpUri = 'https://api.example.com/profile';

        const proof = await createDPoPProof(
            httpMethod,
            httpUri,
            clientKeyPair.privateKey,
            clientKeyPair.publicKeyJwk
        );

        // First verification succeeds
        const first = await verifyDPoPProof(proof, httpMethod, httpUri, { replayStore });
        expect(first.valid).toBe(true);

        // Second verification with identical proof should be rejected as replay
        const second = await verifyDPoPProof(proof, httpMethod, httpUri, { replayStore });
        expect(second.valid).toBe(false);
        expect(second.error).toContain('replay');
    });
});
