import { createDPoPAuth, createSimpleDPoPAuth } from '../index';

describe('Simplified API', () => {
  const SECRET_KEY = 'test-secret-key-for-testing-only';

  describe('createDPoPAuth', () => {
    it('should create DPoPAuth instance with default config', () => {
      const auth = createDPoPAuth(SECRET_KEY);
      
      expect(auth).toBeDefined();
      expect(auth.getConfig().algorithm).toBe('ES256');
      expect(auth.getConfig().expiresIn).toBe(300);
      expect(auth.getConfig().enableFingerprinting).toBe(true);
    });

    it('should create DPoPAuth instance with custom config', () => {
      const auth = createDPoPAuth(SECRET_KEY, {
        algorithm: 'RS256',
        expiresIn: 600,
        enableFingerprinting: false,
      });
      
      expect(auth.getConfig().algorithm).toBe('RS256');
      expect(auth.getConfig().expiresIn).toBe(600);
      expect(auth.getConfig().enableFingerprinting).toBe(false);
    });

    it('should throw error for missing secret', () => {
      expect(() => createDPoPAuth('')).toThrow('Secret key is required');
    });
  });

  describe('DPoPAuth instance methods', () => {
    let auth: ReturnType<typeof createDPoPAuth>;

    beforeEach(() => {
      auth = createDPoPAuth(SECRET_KEY);
    });

    it('should generate device keys', async () => {
      const deviceKeys = await auth.generateDeviceKeys();
      
      expect(deviceKeys).toBeDefined();
      expect(deviceKeys.publicKeyJwk).toBeDefined();
      expect(deviceKeys.privateKeyJwk).toBeDefined();
      expect(deviceKeys.thumbprint).toBeDefined();
      expect(deviceKeys.algorithm).toBe('ES256');
    });

    it('should create auth flow', async () => {
      const deviceKeys = await auth.generateDeviceKeys();
      const authFlow = await auth.createAuthFlow('user123', deviceKeys.publicKeyJwk);
      
      expect(authFlow).toBeDefined();
      expect(authFlow.accessToken).toBeDefined();
      expect(authFlow.refreshToken).toBeDefined();
      expect(authFlow.expiresIn).toBe(300);
      expect(authFlow.tokenType).toBe('DPoP');
    });

    it('should refresh access token', async () => {
      const deviceKeys = await auth.generateDeviceKeys();
      const authFlow = await auth.createAuthFlow('user123', deviceKeys.publicKeyJwk);
      
      const newToken = await auth.refreshAccessToken(
        authFlow.refreshToken.token,
        deviceKeys.publicKeyJwk
      );
      
      expect(newToken).toBeDefined();
      expect(newToken.token).toBeDefined();
      expect(newToken.expiresAt).toBeDefined();
      expect(newToken.jti).toBeDefined();
    });

    it('should verify token', async () => {
      const deviceKeys = await auth.generateDeviceKeys();
      const authFlow = await auth.createAuthFlow('user123', deviceKeys.publicKeyJwk);
      
      const verification = await auth.verifyToken(authFlow.accessToken.token);
      
      expect(verification.valid).toBe(true);
      expect(verification.payload?.sub).toBe('user123');
    });

    it('should generate fingerprint', () => {
      const components = {
        userAgent: 'Mozilla/5.0 (Test)',
        acceptLanguage: 'en-US',
      };
      
      const fingerprint = auth.generateFingerprint(components);
      
      expect(fingerprint).toBeDefined();
      expect(typeof fingerprint).toBe('string');
      expect(fingerprint.length).toBeGreaterThan(0);
    });

    it('should create DPoP proof', async () => {
      const deviceKeys = await auth.generateDeviceKeys();
      const authFlow = await auth.createAuthFlow('user123', deviceKeys.publicKeyJwk);
      
      const dpopProof = await auth.createDPoPProof(
        'GET',
        'https://api.example.com/test',
        deviceKeys.privateKey,
        deviceKeys.publicKeyJwk,
        authFlow.accessToken.token
      );
      
      expect(dpopProof).toBeDefined();
      expect(typeof dpopProof).toBe('string');
      expect(dpopProof.split('.')).toHaveLength(3); // JWT format
    });
  });

  describe('createSimpleDPoPAuth', () => {
    it('should create simplified auth setup', async () => {
      const setup = await createSimpleDPoPAuth(SECRET_KEY);
      
      expect(setup).toBeDefined();
      expect(setup.auth).toBeDefined();
      expect(setup.middleware).toBeDefined();
      expect(setup.generateDeviceKeys).toBeDefined();
      expect(setup.createAuthFlow).toBeDefined();
      expect(setup.refreshToken).toBeDefined();
    });

    it('should work with the simplified functions', async () => {
      const { generateDeviceKeys, createAuthFlow, refreshToken } = 
        await createSimpleDPoPAuth(SECRET_KEY);
      
      // Generate device keys
      const deviceKeys = await generateDeviceKeys();
      expect(deviceKeys.thumbprint).toBeDefined();
      
      // Create auth flow
      const authFlow = await createAuthFlow('user123', deviceKeys.publicKeyJwk);
      expect(authFlow.tokenType).toBe('DPoP');
      
      // Refresh token
      const newToken = await refreshToken(
        authFlow.refreshToken.token,
        deviceKeys.publicKeyJwk
      );
      expect(newToken.token).toBeDefined();
    });
  });
});
