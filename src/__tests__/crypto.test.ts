import {
  generateDPoPKeyPair,
  importDPoPKey,
  generateJTI,
  generateSecureRandom,
  createAccessTokenHash,
  generateFingerprintHash,
  validateFingerprintComponents,
  validateTimestamp,
} from '../core/crypto';

describe('Crypto Functions', () => {
  describe('generateDPoPKeyPair', () => {
    it('should generate ES256 key pair by default', async () => {
      const keyPair = await generateDPoPKeyPair();
      
      expect(keyPair.algorithm).toBe('ES256');
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKeyJwk).toBeDefined();
      expect(keyPair.privateKeyJwk).toBeDefined();
      expect(keyPair.thumbprint).toBeDefined();
      expect(typeof keyPair.thumbprint).toBe('string');
    });

    it('should generate RS256 key pair when specified', async () => {
      const keyPair = await generateDPoPKeyPair({ algorithm: 'RS256' });
      
      expect(keyPair.algorithm).toBe('RS256');
      expect(keyPair.publicKeyJwk.kty).toBe('RSA');
    });

    it('should throw error for unsupported algorithm', async () => {
      await expect(
        generateDPoPKeyPair({ algorithm: 'HS256' as any })
      ).rejects.toThrow('Unsupported algorithm');
    });
  });

  describe('importDPoPKey', () => {
    it('should import a valid JWK key', async () => {
      const keyPair = await generateDPoPKeyPair();
      const imported = await importDPoPKey(keyPair.publicKeyJwk, 'ES256');
      
      expect(imported.key).toBeDefined();
      expect(imported.thumbprint).toBe(keyPair.thumbprint);
      expect(imported.jwk).toEqual(keyPair.publicKeyJwk);
    });

    it('should throw error for invalid JWK', async () => {
      await expect(
        importDPoPKey({ invalid: 'jwk' }, 'ES256')
      ).rejects.toThrow('Failed to import key');
    });
  });

  describe('generateJTI', () => {
    it('should generate unique JTI values', () => {
      const jti1 = generateJTI();
      const jti2 = generateJTI();
      
      expect(jti1).not.toBe(jti2);
      expect(typeof jti1).toBe('string');
      expect(jti1.length).toBe(32); // 16 bytes = 32 hex chars
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate random string of specified length', () => {
      const random = generateSecureRandom(16);
      
      expect(typeof random).toBe('string');
      expect(random.length).toBe(32); // 16 bytes = 32 hex chars
    });
  });

  describe('createAccessTokenHash', () => {
    it('should create consistent hash for same token', () => {
      const token = 'test-access-token';
      const hash1 = createAccessTokenHash(token);
      const hash2 = createAccessTokenHash(token);
      
      expect(hash1).toBe(hash2);
      expect(typeof hash1).toBe('string');
    });

    it('should create different hashes for different tokens', () => {
      const hash1 = createAccessTokenHash('token1');
      const hash2 = createAccessTokenHash('token2');
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('generateFingerprintHash', () => {
    it('should generate consistent hash for same components', () => {
      const components = {
        userAgent: 'Mozilla/5.0 (Test)',
        acceptLanguage: 'en-US,en;q=0.9',
        timezoneOffset: -300,
      };
      
      const hash1 = generateFingerprintHash(components);
      const hash2 = generateFingerprintHash(components);
      
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different components', () => {
      const components1 = { userAgent: 'Mozilla/5.0 (Test1)' };
      const components2 = { userAgent: 'Mozilla/5.0 (Test2)' };
      
      const hash1 = generateFingerprintHash(components1);
      const hash2 = generateFingerprintHash(components2);
      
      expect(hash1).not.toBe(hash2);
    });

    it('should normalize component values', () => {
      const components1 = { userAgent: 'Mozilla/5.0 (Test)' };
      const components2 = { userAgent: 'MOZILLA/5.0 (TEST)' };
      
      const hash1 = generateFingerprintHash(components1);
      const hash2 = generateFingerprintHash(components2);
      
      expect(hash1).toBe(hash2);
    });
  });

  describe('validateFingerprintComponents', () => {
    it('should validate valid components', () => {
      const components = {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        acceptLanguage: 'en-US,en;q=0.9',
        timezoneOffset: -300,
      };
      
      const result = validateFingerprintComponents(components);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('should reject empty components', () => {
      const components = {};
      
      const result = validateFingerprintComponents(components);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('At least one valid component is required');
    });

    it('should reject null components', () => {
      const result = validateFingerprintComponents(null as any);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Components must be an object');
    });

    it('should validate components with some empty values', () => {
      const components = {
        userAgent: 'Mozilla/5.0 (Test)',
        acceptLanguage: '', // Empty value should be ignored
        timezoneOffset: -300,
      };
      
      const result = validateFingerprintComponents(components);
      
      expect(result.valid).toBe(true);
    });
  });

  describe('validateTimestamp', () => {
    it('should validate current timestamp', () => {
      const now = Math.floor(Date.now() / 1000);
      const result = validateTimestamp(now);
      
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should validate timestamp within tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      const result = validateTimestamp(now - 30, 60); // 30 seconds ago, 60s tolerance
      
      expect(result.valid).toBe(true);
    });

    it('should reject timestamp outside tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      const result = validateTimestamp(now - 120, 60); // 2 minutes ago, 60s tolerance
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Timestamp too far from current time');
    });
  });
});
