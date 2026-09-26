import { dpopAuth, requireDevice, requireUser } from '../middleware/express';
import { generateDPoPKeyPair } from '../core/crypto';
import { createAccessToken } from '../core/tokens';
import { createDPoPProof } from '../core/dpop';

describe('Express Middleware', () => {
    const secret = 'super-secret-key-32-chars-long-minimum!';
    let keyPair: Awaited<ReturnType<typeof generateDPoPKeyPair>>;
    let accessToken: string;
    const requestUrl = '/api/protected';
    const fullUri = 'http://localhost/api/protected';

    beforeAll(async () => {
        keyPair = await generateDPoPKeyPair();
        const tokenResult = await createAccessToken('user_123', keyPair.publicKeyJwk, secret);
        accessToken = tokenResult.token;
    });

    const createMockReqRes = (headers: Record<string, string> = {}, method: string = 'GET', url: string = requestUrl) => {
        const req: any = {
            method,
            originalUrl: url,
            url,
            headers: {
                host: 'localhost',
                'user-agent': 'Jest-Test-Agent/1.0',
                'accept-language': 'en-US',
                'accept-encoding': 'gzip, deflate',
                ...headers,
            },
            get(header: string) {
                return this.headers[header.toLowerCase()];
            },
        };

        const res: any = {
            statusCode: 200,
            body: null,
            status(code: number) {
                this.statusCode = code;
                return this;
            },
            json(data: any) {
                this.body = data;
                return this;
            },
        };

        const next = jest.fn();

        return { req, res, next };
    };

    describe('dpopAuth middleware', () => {
        it('should authenticate successfully with Bearer scheme', async () => {
            const proof = await createDPoPProof('GET', fullUri, keyPair.privateKey, keyPair.publicKeyJwk, {
                accessToken,
            });

            const { req, res, next } = createMockReqRes({
                authorization: `Bearer ${accessToken}`,
                dpop: proof,
            });

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).toHaveBeenCalled();
            expect(req.token?.sub).toBe('user_123');
            expect(req.dpop).toBeDefined();
            expect(req.thumbprint).toBe(keyPair.thumbprint);
        });

        it('should authenticate successfully with DPoP scheme (Bug #1 verification)', async () => {
            const proof = await createDPoPProof('GET', fullUri, keyPair.privateKey, keyPair.publicKeyJwk, {
                accessToken,
            });

            const { req, res, next } = createMockReqRes({
                authorization: `DPoP ${accessToken}`,
                dpop: proof,
            });

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).toHaveBeenCalled();
            expect(req.token?.sub).toBe('user_123');
            expect(req.dpop).toBeDefined();
        });

        it('should reject request missing Authorization header', async () => {
            const { req, res, next } = createMockReqRes();

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(401);
            expect(res.body?.message).toContain('Missing or invalid Authorization header');
        });

        it('should reject request with unsupported auth scheme', async () => {
            const { req, res, next } = createMockReqRes({
                authorization: `Basic ${accessToken}`,
            });

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(401);
            expect(res.body?.message).toContain('Missing or invalid Authorization header');
        });

        it('should reject request missing DPoP header', async () => {
            const { req, res, next } = createMockReqRes({
                authorization: `Bearer ${accessToken}`,
            });

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(401);
            expect(res.body?.message).toContain('Missing DPoP header');
        });

        it('should reject request when DPoP key does not match token thumbprint', async () => {
            const otherKeyPair = await generateDPoPKeyPair();
            const proof = await createDPoPProof('GET', fullUri, otherKeyPair.privateKey, otherKeyPair.publicKeyJwk, {
                accessToken,
            });

            const { req, res, next } = createMockReqRes({
                authorization: `Bearer ${accessToken}`,
                dpop: proof,
            });

            const middleware = dpopAuth({ secret, enableFingerprinting: false });
            await middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(403);
            expect(res.body?.message).toContain('Device key mismatch');
        });
    });

    describe('requireDevice and requireUser helpers', () => {
        it('should allow matching device thumbprint', () => {
            const { req, res, next } = createMockReqRes();
            req.thumbprint = keyPair.thumbprint;

            const checkDevice = requireDevice(keyPair.thumbprint);
            checkDevice(req, res, next);

            expect(next).toHaveBeenCalled();
        });

        it('should reject non-matching device thumbprint', () => {
            const { req, res, next } = createMockReqRes();
            req.thumbprint = 'different_thumbprint';

            const checkDevice = requireDevice(keyPair.thumbprint);
            checkDevice(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(403);
        });

        it('should allow matching user', () => {
            const { req, res, next } = createMockReqRes();
            req.token = { sub: 'user_123' };

            const checkUser = requireUser('user_123');
            checkUser(req, res, next);

            expect(next).toHaveBeenCalled();
        });

        it('should reject non-matching user', () => {
            const { req, res, next } = createMockReqRes();
            req.token = { sub: 'user_456' };

            const checkUser = requireUser('user_123');
            checkUser(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.statusCode).toBe(403);
        });
    });
});
