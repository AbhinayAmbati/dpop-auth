# 🛡️ DPoP Auth - Modern Device-Bound Authentication

[![npm version](https://badge.fury.io/js/dpop-auth.svg)](https://badge.fury.io/js/dpop-auth)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![ESM](https://img.shields.io/badge/ESM-Ready-brightgreen.svg)](https://nodejs.org/api/esm.html)

A **modern, simplified** Node.js library for implementing **DPoP (Demonstration of Proof-of-Possession)** authentication. Features a clean API, full TypeScript support, modern ESM standards, and reduced boilerplate for enterprise-grade security.

## 🆕 What's New in v1.1.0

- **🚀 Simplified API** - New `createSimpleDPoPAuth()` for quick setup
- **📦 Modern ESM** - Full ES modules support with backward compatibility  
- **🔧 Better TypeScript** - Enhanced type definitions and automatic typing
- **⚡ Reduced Boilerplate** - 70% less code for common use cases
- **🎯 Improved DX** - Better developer experience with cleaner methods
- **🔄 Backward Compatible** - All v1.0.0 code continues to work

## 🌟 Features

- **🔐 Device-Bound Tokens** - Access tokens cryptographically bound to device keys
- **🛡️ DPoP Authentication** - RFC 9449 compliant proof-of-possession tokens
- **🚫 Anti-Replay Protection** - Prevents token replay attacks with JTI tracking
- **👤 Fingerprint Binding** - Advanced device fingerprinting for enhanced security
- **⚡ Express Middleware** - Zero-config middleware for Express applications
- **🔄 Refresh Token Flow** - Secure token refresh with device binding
- **🔧 Full TypeScript** - Complete type definitions with automatic inference
- **📦 Modern ESM** - ES modules with CommonJS compatibility
- **🎯 Simplified API** - Reduced boilerplate, same enterprise security
- **🧪 Battle-Tested** - Comprehensive test coverage and production-ready

## 📦 Installation

```bash
npm install dpop-auth
```

**Requirements:**
- Node.js 18+ (for modern crypto and ESM support)
- TypeScript 5+ (for full type support)
- Express 4+ (for middleware)

## 🚀 Quick Start

### 1. Ultra-Simple Setup (Recommended)

```javascript
import { createSimpleDPoPAuth } from 'dpop-auth';

// One-line setup with everything pre-configured
const { auth, middleware, generateDeviceKeys, createAuthFlow } = 
  await createSimpleDPoPAuth('your-super-secret-key');

// Use the pre-configured middleware
app.use('/api/protected', middleware);

// Generate device keys
const deviceKeys = await generateDeviceKeys();

// Create authentication flow
const tokens = await createAuthFlow('user123', deviceKeys.publicKeyJwk);
```

### 2. Traditional Setup (Advanced)

```javascript
import { createDPoPAuth } from 'dpop-auth';

// Initialize with your secret key
const dpopAuth = createDPoPAuth('your-super-secret-key');

// Or with custom configuration
const dpopAuth = createDPoPAuth('your-secret', {
  algorithm: 'ES256',
  expiresIn: 300, // 5 minutes
  enableFingerprinting: true,
});
```

### 3. Express Middleware

```javascript
import express from 'express';
import { createDPoPAuth } from 'dpop-auth';

const app = express();
const dpopAuth = createDPoPAuth('your-secret-key');

// NEW: Simplified middleware setup
app.use('/api/protected', dpopAuth.middleware());

// Or use the ultra-simple approach
// const { middleware } = await createSimpleDPoPAuth('your-secret');
// app.use('/api/protected', middleware);

app.get('/api/protected/data', (req, res) => {
  // Access authenticated user info
  console.log('User ID:', req.token.sub);
  console.log('Device thumbprint:', req.thumbprint);
  
  res.json({ message: 'Secure data', userId: req.token.sub });
});
```

### 4. Complete Authentication Flow

```javascript
import { createDPoPAuth } from 'dpop-auth';

const dpopAuth = createDPoPAuth('your-secret-key');

// 1. Generate device keys (server-side for demo)
const deviceKeys = await dpopAuth.generateDeviceKeys();

// 2. Create authentication flow
const authFlow = await dpopAuth.createAuthFlow(
  'user123', 
  deviceKeys.publicKeyJwk,
  'optional-fingerprint'
);

console.log(authFlow);
// {
//   accessToken: { token: '...', expiresAt: 1234567890, jti: '...' },
//   refreshToken: { token: '...', expiresAt: 1234567890, jti: '...' },
//   expiresIn: 300,
//   tokenType: 'DPoP'
// }

// 3. Refresh tokens
const newToken = await dpopAuth.refreshAccessToken(
  authFlow.refreshToken.token,
  deviceKeys.publicKeyJwk
);

// 4. Verify tokens
const verification = await dpopAuth.verifyToken(authFlow.accessToken.token);
console.log(verification.valid); // true
```

### 5. Client-Side Integration (Browser)

```javascript
// Generate device keys in browser
const deviceKeys = await dpopAuth.generateDeviceKeys();

// Create DPoP proof for requests
const dpopProof = await dpopAuth.createDPoPProof(
  'GET',
  'https://api.example.com/protected',
  deviceKeys.privateKey,
  deviceKeys.publicKeyJwk,
  accessToken
);

// Make authenticated request
fetch('/api/protected/data', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'DPoP': dpopProof,
    'Content-Type': 'application/json'
  }
});

const data = await response.json();
console.log('Protected data:', data);
```

## 📚 Complete API Reference

### Main Classes

#### `DPoPAuth`
The main authentication class providing a simplified API.

```javascript
import { createDPoPAuth } from 'dpop-auth';

const auth = createDPoPAuth('your-secret-key', {
  algorithm: 'ES256',
  expiresIn: 300,
  enableFingerprinting: true,
});
```

**Methods:**
- `generateDeviceKeys()` - Generate device key pair
- `createAuthFlow(userId, publicKey, fingerprint?)` - Create access & refresh tokens
- `refreshAccessToken(refreshToken, publicKey, fingerprint?)` - Refresh access token
- `createDPoPProof(method, uri, privateKey, publicKey, accessToken?, fingerprint?)` - Create DPoP proof
- `verifyToken(token)` - Verify access token
- `generateFingerprint(components)` - Generate device fingerprint
- `middleware(options?)` - Get Express middleware
- `getConfig()` - Get current configuration

#### `createSimpleDPoPAuth(secret, options?)`
Ultra-simple setup function for quick start.

```javascript
import { createSimpleDPoPAuth } from 'dpop-auth';

const { auth, middleware, generateDeviceKeys, createAuthFlow, refreshToken } = 
  await createSimpleDPoPAuth('your-secret-key');

// Everything is pre-configured and ready to use
app.use('/api/protected', middleware);
const deviceKeys = await generateDeviceKeys();
const tokens = await createAuthFlow('user123', deviceKeys.publicKeyJwk);
```

### Advanced Functions (Power Users)

#### `generateDPoPKeyPair(options?)`
Generate a cryptographic key pair for DPoP authentication.

```javascript
import { generateDPoPKeyPair } from 'dpop-auth';

const keyPair = await generateDPoPKeyPair({
  algorithm: 'ES256', // or 'RS256'
  curve: 'P-256',     // for EC keys
  keySize: 2048       // for RSA keys
});

console.log(keyPair.thumbprint); // Device key thumbprint
```

#### `createAccessToken(subject, devicePublicKeyJwk, secret, options?)`
Create a device-bound access token.

```javascript
import { createAccessToken } from 'dpop-auth';

const token = await createAccessToken(
  'user123',           // User ID
  publicKeyJwk,        // Device public key
  'your-secret',       // Signing secret
  {
    expiresIn: 300,    // 5 minutes
    fingerprint: 'fp-hash',
    customClaims: { role: 'admin' }
  }
);

console.log(token.token);     // JWT token
console.log(token.expiresAt); // Expiration timestamp
```

#### `verifyAccessToken(token, secret, options?)`
Verify and decode an access token.

```javascript
import { verifyAccessToken } from 'dpop-auth';

const result = await verifyAccessToken(token, 'your-secret');

if (result.valid) {
  console.log('User ID:', result.payload.sub);
  console.log('Device thumbprint:', result.payload.cnf.jkt);
} else {
  console.error('Invalid token:', result.error);
}
```

#### `createDPoPProof(method, uri, privateKey, publicKeyJwk, options?)`
Create a DPoP proof JWT.

```javascript
import { createDPoPProof } from 'dpop-auth';

const proof = await createDPoPProof(
  'POST',
  'https://api.example.com/data',
  privateKey,
  publicKeyJwk,
  {
    accessToken: 'access-token-here',
    fingerprint: 'fingerprint-hash'
  }
);
```

#### `verifyDPoPProof(proof, method, uri, options?)`
Verify a DPoP proof JWT.

```javascript
import { verifyDPoPProof, MemoryReplayStore } from 'dpop-auth';

const replayStore = new MemoryReplayStore();

const result = await verifyDPoPProof(
  dpopProof,
  'POST',
  'https://api.example.com/data',
  {
    accessToken: 'access-token',
    replayStore,
    expectedFingerprint: 'fingerprint-hash'
  }
);

if (result.valid) {
  console.log('Valid DPoP proof');
  console.log('Device thumbprint:', result.thumbprint);
}
```

### Fingerprinting

#### `generateFingerprintHash(components)`
Generate a device fingerprint hash.

```javascript
import { generateFingerprintHash } from 'dpop-auth';

const fingerprint = generateFingerprintHash({
  userAgent: req.get('user-agent'),
  acceptLanguage: req.get('accept-language'),
  acceptEncoding: req.get('accept-encoding'),
  screenResolution: '1920x1080',
  timezoneOffset: -300
});
```

### Express Middleware

#### `dpopAuth(options)`
Main authentication middleware.

```javascript
import { dpopAuth } from 'dpop-auth';

app.use(dpopAuth({
  secret: 'your-secret',
  algorithm: 'ES256',
  expiresIn: 300,
  clockTolerance: 60,
  enableFingerprinting: true,
  replayStore: new MemoryReplayStore(),
  onError: (error, req, res, next) => {
    res.status(401).json({ error: error.message });
  }
}));
```

#### `optionalDPoPAuth(options)`
Optional authentication middleware.

```javascript
import { optionalDPoPAuth } from 'dpop-auth';

// Authentication is optional - continues without auth if no token provided
app.use(optionalDPoPAuth({ secret: 'your-secret' }));
```

#### `requireDevice(thumbprint)`
Require specific device.

```javascript
import { requireDevice } from 'dpop-auth';

// Only allow specific device
app.use('/admin', requireDevice('device-thumbprint-here'));
```

### Utility Class

#### `DPoPAuth` Class
High-level utility class for common operations.

```javascript
import { DPoPAuth } from 'dpop-auth';

const auth = new DPoPAuth('your-secret', {
  algorithm: 'ES256',
  expiresIn: 300,
  enableFingerprinting: true
});

// Create complete auth flow
const authFlow = await auth.createAuthFlow(
  'user123',
  devicePublicKeyJwk,
  fingerprintHash
);

console.log(authFlow.accessToken);
console.log(authFlow.refreshToken);

// Refresh access token
const newAccessToken = await auth.refreshAccessToken(
  refreshToken,
  devicePublicKeyJwk,
  fingerprintHash
);

// Get configured middleware
app.use('/api', auth.getMiddleware());
```

## 🔧 Configuration Options

### DPoPConfig

```typescript
interface DPoPConfig {
  algorithm?: 'ES256' | 'RS256';     // Signing algorithm (default: ES256)
  expiresIn?: number;                // Token expiration in seconds (default: 300)
  clockTolerance?: number;           // Clock skew tolerance (default: 60)
  maxAge?: number;                   // Max age for replay protection (default: 300)
  enableFingerprinting?: boolean;    // Enable fingerprint binding (default: true)
  issuer?: string;                   // Token issuer (default: 'dpop-auth')
  audience?: string;                 // Token audience (default: 'dpop-auth')
}
```

### MiddlewareOptions

```typescript
interface MiddlewareOptions extends DPoPConfig {
  secret: string | KeyLike;         // Secret for token verification
  replayStore?: ReplayStore;        // Replay protection store
  skipDPoP?: boolean;               // Skip DPoP validation (testing only)
  onError?: (error, req, res, next) => void; // Custom error handler
}
```

## 🛡️ Security Considerations

### ✅ Best Practices

1. **Use HTTPS Always** - DPoP tokens must be transmitted over HTTPS
2. **Secure Key Storage** - Store private keys securely (server env or KMS)
3. **Short Token Lifetimes** - Use short expiration times (5-15 minutes)
4. **Implement Replay Protection** - Use a persistent replay store in production
5. **Rate Limit Token Endpoints** - Prevent brute force attacks
6. **Validate Fingerprints** - Use fingerprinting for additional security
7. **Monitor for Anomalies** - Log and monitor authentication patterns

### 🔒 Security Features

- **Device Binding** - Tokens are cryptographically bound to device keys
- **Replay Protection** - JTI tracking prevents token replay attacks
- **Clock Skew Tolerance** - Configurable tolerance for time synchronization
- **Fingerprint Validation** - Optional device fingerprinting
- **Algorithm Support** - Both EC (ES256) and RSA (RS256) algorithms
- **Secure Defaults** - Security-first default configuration

### ⚠️ Important Notes

- **Private Key Security** - Never expose private keys to clients
- **HTTPS Required** - Always use HTTPS in production
- **Replay Store** - Use persistent storage for replay protection in production
- **Clock Synchronization** - Ensure server clocks are synchronized
- **Key Rotation** - Implement regular key rotation policies

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 📖 Migration Guide

### From Standard JWT

```javascript
// Before (standard JWT)
app.use(jwt({ secret: 'secret' }));

// After (DPoP Auth)
app.use(dpopAuth({ 
  secret: 'secret',
  algorithm: 'ES256',
  enableFingerprinting: true
}));
```

### Integration Steps

1. **Generate Device Keys** - Implement client-side key generation
2. **Update Token Creation** - Use `createAccessToken` with device binding
3. **Add DPoP Proofs** - Create DPoP proofs for each API request
4. **Update Middleware** - Replace JWT middleware with `dpopAuth`
5. **Implement Replay Store** - Add persistent replay protection
6. **Test Thoroughly** - Verify all authentication flows work correctly

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/abhinayambati/dpop-auth/wiki)
- **Issues**: [GitHub Issues](https://github.com/abhinayambati/dpop-auth/issues)
- **Security**: Report security issues to abhinayambati4@gmail.com

---

**Built with ❤️ and 🛡️ for secure authentication**

## 🛡️ Security Best Practices

### 1. Secret Key Management
```javascript
// ❌ Don't hardcode secrets
const auth = createDPoPAuth('hardcoded-secret');

// ✅ Use environment variables
const auth = createDPoPAuth(process.env.DPOP_SECRET);

// ✅ Use key management services
const secret = await getSecretFromVault('dpop-secret');
const auth = createDPoPAuth(secret);
```

### 2. Device Key Storage
```javascript
// Client-side: Store keys securely
const deviceKeys = await auth.generateDeviceKeys();

// Store in secure storage (not localStorage)
if ('indexedDB' in window) {
  await storeInIndexedDB('device-keys', deviceKeys);
} else {
  // Fallback for older browsers
  sessionStorage.setItem('device-keys', JSON.stringify(deviceKeys));
}
```

### 3. Fingerprint Components
```javascript
// Collect comprehensive fingerprint data
const fingerprintComponents = {
  userAgent: navigator.userAgent,
  language: navigator.language,
  platform: navigator.platform,
  screenResolution: `${screen.width}x${screen.height}`,
  timezoneOffset: new Date().getTimezoneOffset(),
  // Add more components as needed
};

const fingerprint = auth.generateFingerprint(fingerprintComponents);
```

### 4. Error Handling
```javascript
try {
  const authFlow = await auth.createAuthFlow(userId, deviceKey, fingerprint);
  // Handle success
} catch (error) {
  if (error.message.includes('Invalid device key')) {
    // Handle device key issues
  } else if (error.message.includes('Fingerprint mismatch')) {
    // Handle fingerprint issues
  } else {
    // Handle other errors
  }
}
```

## 🔄 Migration from v1.0.0

### Automatic Migration (No Changes Needed)
Your existing v1.0.0 code will continue to work:

```javascript
// This still works exactly the same
import { createDPoPAuth, dpopAuth, generateDPoPKeyPair } from 'dpop-auth';

const auth = createDPoPAuth('secret');
const keyPair = await generateDPoPKeyPair();
app.use('/protected', dpopAuth({ secret: 'secret' }));
```

### Recommended Upgrade Path

#### Step 1: Replace Complex Setup
```javascript
// Old way (v1.0.0)
const auth = createDPoPAuth(SECRET, config);
const keyPair = await generateDPoPKeyPair();
const accessToken = await createAccessToken(userId, keyPair.publicKeyJwk, SECRET, config);
const refreshToken = await createRefreshToken(userId, keyPair.publicKeyJwk, SECRET, config);

// New way (v1.1.0)
const auth = createDPoPAuth(SECRET, config);
const deviceKeys = await auth.generateDeviceKeys();
const { accessToken, refreshToken } = await auth.createAuthFlow(userId, deviceKeys.publicKeyJwk);
```

#### Step 2: Simplify Middleware
```javascript
// Old way (v1.0.0)
app.use('/protected', dpopAuth({
  secret: SECRET,
  algorithm: 'ES256',
  enableFingerprinting: true,
}));

// New way (v1.1.0)
const auth = createDPoPAuth(SECRET, { algorithm: 'ES256', enableFingerprinting: true });
app.use('/protected', auth.middleware());
```

#### Step 3: Use Ultra-Simple Setup (Optional)
```javascript
// Ultra-simple setup for new projects
const { auth, middleware, generateDeviceKeys, createAuthFlow } = 
  await createSimpleDPoPAuth(SECRET);

app.use('/protected', middleware);
const deviceKeys = await generateDeviceKeys();
const tokens = await createAuthFlow(userId, deviceKeys.publicKeyJwk);
```

## 🧪 Testing

### Unit Testing
```javascript
import { createDPoPAuth } from 'dpop-auth';

describe('DPoP Authentication', () => {
  const auth = createDPoPAuth('test-secret');

  test('should generate device keys', async () => {
    const deviceKeys = await auth.generateDeviceKeys();
    expect(deviceKeys.thumbprint).toBeDefined();
    expect(deviceKeys.algorithm).toBe('ES256');
  });

  test('should create auth flow', async () => {
    const deviceKeys = await auth.generateDeviceKeys();
    const authFlow = await auth.createAuthFlow('user123', deviceKeys.publicKeyJwk);
    
    expect(authFlow.accessToken).toBeDefined();
    expect(authFlow.refreshToken).toBeDefined();
    expect(authFlow.tokenType).toBe('DPoP');
  });
});
```

### Integration Testing
```javascript
import request from 'supertest';
import app from './app';

describe('Protected Routes', () => {
  let accessToken, dpopProof;

  beforeEach(async () => {
    // Setup authentication
    const auth = createDPoPAuth(process.env.TEST_SECRET);
    const deviceKeys = await auth.generateDeviceKeys();
    const authFlow = await auth.createAuthFlow('test-user', deviceKeys.publicKeyJwk);
    
    accessToken = authFlow.accessToken.token;
    dpopProof = await auth.createDPoPProof(
      'GET', 
      'http://localhost/api/protected/data',
      deviceKeys.privateKey,
      deviceKeys.publicKeyJwk,
      accessToken
    );
  });

  test('should access protected route with valid DPoP', async () => {
    const response = await request(app)
      .get('/api/protected/data')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('DPoP', dpopProof);

    expect(response.status).toBe(200);
    expect(response.body.user).toBe('test-user');
  });
});
```

## 🚀 Performance Tips

### 1. Reuse Auth Instances
```javascript
// ✅ Create once, reuse everywhere
const auth = createDPoPAuth(SECRET);
export default auth;

// ❌ Don't create new instances repeatedly
const auth1 = createDPoPAuth(SECRET);
const auth2 = createDPoPAuth(SECRET); // Unnecessary
```

### 2. Cache Device Keys
```javascript
// Cache device keys to avoid regeneration
let cachedDeviceKeys = null;

async function getDeviceKeys() {
  if (!cachedDeviceKeys) {
    cachedDeviceKeys = await auth.generateDeviceKeys();
  }
  return cachedDeviceKeys;
}
```

### 3. Use Replay Store Cleanup
```javascript
import { cleanupReplayStore, MemoryReplayStore } from 'dpop-auth';

const replayStore = new MemoryReplayStore();

// Cleanup expired entries every 5 minutes
const cleanup = cleanupReplayStore(replayStore, 5 * 60 * 1000);

// Stop cleanup when shutting down
process.on('SIGTERM', () => {
  cleanup();
});
```

## 🔗 Related Resources

- **RFC 9449**: [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- **JOSE Library**: [JavaScript Object Signing and Encryption](https://github.com/panva/jose)
- **Express.js**: [Web framework for Node.js](https://expressjs.com/)
- **TypeScript**: [Typed JavaScript at scale](https://www.typescriptlang.org/)
