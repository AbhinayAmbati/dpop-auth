# DPoP Auth 🔐

[![npm version](https://img.shields.io/npm/v/dpop-auth.svg)](https://www.npmjs.com/package/dpop-auth)
[![License](https://img.shields.io/npm/l/dpop-auth.svg)](https://github.com/abhinayambati/dpop-auth/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

**Device-bound authentication with DPoP (Demonstration of Proof-of-Possession) tokens for enhanced API security.**

DPoP Auth prevents token theft and replay attacks by cryptographically binding tokens to specific devices. Perfect for securing APIs against unauthorized access, credential stuffing, and token exfiltration.

## ✨ Features

- 🔒 **Device-Bound Tokens** - Cryptographic binding prevents token theft
- 🛡️ **Anti-Replay Protection** - Built-in nonce and JTI tracking
- 🖐️ **Fingerprint Binding** - Optional device fingerprint integration
- ⚡ **High Performance** - LRU caching for cryptographic operations
- 🔄 **Token Rotation** - Grace period support for seamless rotation
- ❌ **Token Revocation** - Immediate token invalidation support
- 🚦 **Rate Limiting** - Sliding window & token bucket algorithms
- 📦 **Redis Support** - Production-ready distributed stores
- 🎯 **Express Middleware** - Ready-to-use authentication middleware
- 📝 **TypeScript Native** - Full type safety and IntelliSense

## 📦 Installation

```bash
npm install dpop-auth
```

## 🚀 Quick Start

### Server-Side (Express)

```typescript
import { DPoPAuth, dpopAuth, generateDPoPKeyPair } from 'dpop-auth';

// Initialize DPoP Auth
const auth = new DPoPAuth(process.env.JWT_SECRET!, {
  algorithm: 'ES256',
  expiresIn: 300, // 5 minutes
  enableFingerprinting: true,
});

// Create tokens for a user
app.post('/login', async (req, res) => {
  const { userId, devicePublicKey } = req.body;
  
  const tokens = await auth.createAuthFlow(userId, devicePublicKey);
  
  res.json({
    accessToken: tokens.accessToken.token,
    refreshToken: tokens.refreshToken.token,
    expiresIn: tokens.expiresIn,
  });
});

// Protect routes with DPoP middleware
app.get('/api/protected', dpopAuth({
  secret: process.env.JWT_SECRET!,
  algorithm: 'ES256',
}), (req, res) => {
  res.json({ user: req.user });
});
```

### Client-Side

```typescript
import { generateDPoPKeyPair, createDPoPProof } from 'dpop-auth';

// Generate device key pair (store securely!)
const keyPair = await generateDPoPKeyPair({ algorithm: 'ES256' });

// Login and get tokens
const response = await fetch('/login', {
  method: 'POST',
  body: JSON.stringify({
    userId: 'user123',
    devicePublicKey: keyPair.publicKeyJwk,
  }),
});
const { accessToken } = await response.json();

// Make authenticated requests
const proof = await createDPoPProof(
  'GET',
  'https://api.example.com/data',
  keyPair.privateKey,
  keyPair.publicKeyJwk,
  { accessToken }
);

const data = await fetch('https://api.example.com/data', {
  headers: {
    'Authorization': `DPoP ${accessToken}`,
    'DPoP': proof,
  },
});
```

## 🔧 Advanced Features

### Rate Limiting

```typescript
import { SlidingWindowRateLimiter, createRateLimiterMiddleware } from 'dpop-auth';

const limiter = new SlidingWindowRateLimiter({
  maxRequests: 100,
  windowMs: 60000, // 1 minute
});

app.use('/api', createRateLimiterMiddleware({ limiter }));
```

### Token Revocation

```typescript
import { MemoryRevocationStore } from 'dpop-auth';

const revocationStore = new MemoryRevocationStore();

const auth = new DPoPAuth(secret, { revocationStore });

// Revoke a token
await auth.revokeToken(accessToken);
```

### Redis for Production

```typescript
import { RedisReplayStore, RedisRevocationStore } from 'dpop-auth';
import { createClient } from 'redis';

const redis = createClient();
await redis.connect();

const replayStore = new RedisReplayStore({ client: redis });
const revocationStore = new RedisRevocationStore({ client: redis });

const auth = new DPoPAuth(secret, {
  replayStore,
  revocationStore,
});
```

### Token Introspection

```typescript
import { introspectToken, getTokenLifetime } from 'dpop-auth';

const info = introspectToken(accessToken);
console.log(info);
// {
//   active: true,
//   tokenType: 'access',
//   subject: 'user123',
//   expiresAt: 1234567890,
//   deviceThumbprint: 'abc123...',
// }

const lifetime = getTokenLifetime(accessToken);
console.log(`Token expires in ${lifetime.remainingSeconds} seconds`);
```

### Multiple Algorithm Support

```typescript
// ES256 (default, recommended)
const keyPair = await generateDPoPKeyPair({ algorithm: 'ES256' });

// ES384, ES512 for higher security
const keyPair384 = await generateDPoPKeyPair({ algorithm: 'ES384' });

// RSA algorithms
const rsaKeyPair = await generateDPoPKeyPair({ algorithm: 'RS256', keySize: 4096 });

// RSA-PSS algorithms
const pssKeyPair = await generateDPoPKeyPair({ algorithm: 'PS256' });
```

## 📚 API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `generateDPoPKeyPair()` | Generate EC or RSA key pair |
| `createAccessToken()` | Create a device-bound access token |
| `createRefreshToken()` | Create a device-bound refresh token |
| `createDPoPProof()` | Create a DPoP proof for a request |
| `verifyDPoPProof()` | Verify a DPoP proof |

### Middleware

| Function | Description |
|----------|-------------|
| `dpopAuth()` | Express middleware for mandatory DPoP auth |
| `optionalDPoPAuth()` | Express middleware for optional DPoP auth |
| `requireDevice()` | Require specific device thumbprint |
| `requireUser()` | Require specific user ID |

### Utilities

| Function | Description |
|----------|-------------|
| `introspectToken()` | Decode token without verification |
| `validateTokenStructure()` | Validate JWT structure |
| `getTokenLifetime()` | Get remaining token lifetime |
| `validateSecretStrength()` | Check secret security |

### Stores

| Class | Description |
|-------|-------------|
| `MemoryReplayStore` | In-memory replay protection |
| `MemoryRevocationStore` | In-memory token revocation |
| `RedisReplayStore` | Redis-based replay protection |
| `RedisRevocationStore` | Redis-based token revocation |
| `RedisNonceStore` | Redis-based nonce management |
| `RedisDeviceRegistry` | Redis-based device tracking |

## 🔒 Security Best Practices

1. **Use HTTPS** - Always use HTTPS in production
2. **Strong Secrets** - Use 256+ bit secrets for JWT signing
3. **Short Token Lifetimes** - Keep access tokens short-lived (5-15 min)
4. **Replay Protection** - Always enable replay store in production
5. **Rate Limiting** - Protect against brute force attacks
6. **Device Limits** - Limit devices per user to prevent abuse

## 🆚 Version 2.0 Changes

- ✅ Extended algorithm support (ES384, ES512, PS256, PS384, PS512)
- ✅ LRU caching for improved performance
- ✅ Rate limiting (sliding window & token bucket)
- ✅ Token revocation support
- ✅ Redis stores for production
- ✅ Enhanced error handling with error codes
- ✅ Token introspection & rotation utilities
- ✅ Security utilities (constant-time compare, etc.)

## 📄 License

Apache-2.0 © [Abhinay Ambati](https://github.com/abhinayambati)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📮 Support

- 📧 Email: abhinayambati4@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/abhinayambati/dpop-auth/issues)
