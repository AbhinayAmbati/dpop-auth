# 🛡️ DPoP Auth - Device-Bound Authentication

[![npm version](https://badge.fury.io/js/dpop-auth.svg)](https://badge.fury.io/js/dpop-auth)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A comprehensive Node.js library for implementing **DPoP (Demonstration of Proof-of-Possession)** authentication. Provides secure device-bound tokens, anti-replay protection, fingerprint binding, and Express middleware for enterprise-grade security.

## 🌟 Features

- **🔐 Device-Bound Tokens** - Access tokens bound to cryptographic device keys
- **🛡️ DPoP Authentication** - RFC-compliant proof-of-possession tokens
- **🚫 Anti-Replay Protection** - Prevents token replay attacks with JTI tracking
- **👤 Fingerprint Binding** - Optional device fingerprinting for enhanced security
- **⚡ Express Middleware** - Ready-to-use middleware for Express applications
- **🔄 Refresh Token Flow** - Secure token refresh with device binding
- **🔧 TypeScript Support** - Full TypeScript definitions included
- **🧪 Comprehensive Testing** - Extensive test coverage for reliability

## 📦 Installation

```bash
npm install dpop-auth
```

## 🚀 Quick Start

### 1. Basic Setup

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

### 2. Express Middleware

```javascript
import express from 'express';
import { dpopAuth } from 'dpop-auth';

const app = express();

// Protect routes with DPoP authentication
app.use('/api/protected', dpopAuth({
  secret: 'your-secret-key',
  algorithm: 'ES256',
  enableFingerprinting: true,
}));

app.get('/api/protected/data', (req, res) => {
  // Access authenticated user info
  console.log('User ID:', req.token.sub);
  console.log('Device thumbprint:', req.thumbprint);
  
  res.json({ message: 'Secure data', userId: req.token.sub });
});
```

### 3. Client-Side Key Generation (Browser)

```javascript
// Generate device key pair in browser
async function generateDeviceKeys() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["sign", "verify"]
  );
  
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKey = keyPair.privateKey;
  
  return { publicKeyJwk, privateKey };
}

// Create DPoP proof for API requests
async function createDPoPProof(method, url, privateKey, publicKeyJwk, accessToken) {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: publicKeyJwk
  };
  
  const payload = {
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: accessToken ? await hashAccessToken(accessToken) : undefined
  };
  
  // Sign JWT (implementation depends on your JWT library)
  return await signJWT(header, payload, privateKey);
}

// Make authenticated request
async function makeAuthenticatedRequest(url, accessToken, dpopProof) {
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'DPoP': dpopProof,
      'Content-Type': 'application/json'
    }
  });
  
  return response.json();
}
```

## 📚 Complete API Reference

### Core Functions

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
