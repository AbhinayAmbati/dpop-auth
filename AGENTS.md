# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, Codex, etc.) working in this repository. Read this before writing code against `dpop-auth`.

## What this package is

`dpop-auth` is a Node.js/TypeScript library implementing **DPoP (Demonstration of Proof-of-Possession, RFC 9449)** — sender-constrained, device-bound API tokens. A normal JWT authorises whoever holds the string (bearer). With DPoP, every access token is bound to an asymmetric key pair generated on the client device, and every request must carry a fresh, single-use, signed proof JWT. Stolen or replayed tokens are rejected.

- Runtime: Node.js >= 16
- Single runtime dependency: `jose`
- Build: TypeScript -> `dist/`
- Tests: Jest (ts-jest), **80% coverage threshold enforced globally** (branches/functions/lines/statements)
- License: Apache-2.0

## Repository layout

```
src/
  core/
    crypto.ts        # key-pair generation, thumbprints, JTI, fingerprints, hashes
    tokens.ts        # access/refresh token create + verify, expiry helpers
    dpop.ts          # createDPoPProof / verifyDPoPProof, MemoryReplayStore
    security.ts      # secureCompare, secret strength validation
    errors.ts        # DPoPErrorCode enum + DPoPError class
    token-utils.ts   # token parsing helpers
  middleware/
    express.ts       # dpopAuth, optionalDPoPAuth, requireDevice, requireUser
  stores/
    redis.ts         # RedisReplayStore, RedisRevocationStore, RedisNonceStore
  types/index.ts     # all public TypeScript types
  index.ts           # public entry point
examples/            # basic-usage.js, client-side.html
index.html           # project landing page (deployed via GitHub Pages)
.github/workflows/deploy-pages.yml   # Pages deploy workflow
```

## Commands

```bash
npm install
npm run build            # tsc -> dist/
npm test                 # jest
npm run test:coverage    # jest --coverage (threshold: 80%)
npm run lint             # eslint src/**/*.ts
npm run format           # prettier --write
```

Before committing changes to `src/`, run `npm run build && npm test` — CI-style discipline. Do not publish without `npm run prepublishOnly` (build + tests).

## The protocol in one paragraph

At login the client generates an ES256 key pair in the browser (WebCrypto). Only the **public** JWK is sent to the server. The server issues an access token whose `cnf.jkt` claim is the thumbprint of that key (plus an optional `fph` fingerprint hash). On every API call the client signs a short-lived **DPoP proof JWT** (`typ: dpop+jwt`) with the private key; its payload binds the proof to `htm` (method), `htu` (URI), `iat`, `jti` (single-use), and `ath` (hash of the access token). The middleware verifies token signature, thumbprint match, proof signature, `htm`/`htu` match, timestamp window, and that the `jti` has not been seen before (replay store).

## Implementation recipes

### 1. Protect Express routes (server)

```ts
import { dpopAuth, MemoryReplayStore } from 'dpop-auth';

app.use('/api/protected', dpopAuth({
  secret: process.env.DPOP_SECRET,     // REQUIRED, use >= 32 random chars in prod
  algorithm: 'ES256',
  expiresIn: 300,
  enableFingerprinting: true,
  replayStore: new MemoryReplayStore(),
  onError: (err, req, res, next) => res.status(401).json({ error: err.message }),
}));

// After the middleware succeeds:
app.get('/api/protected/data', (req, res) => {
  res.json({ user: req.token.sub, device: req.thumbprint });
});
```

Notes for agents:
- The middleware accepts **both** `Authorization: DPoP <token>` and `Bearer <token>` schemes, but DPoP proofs are always required unless `skipDPoP: true` (testing only — never enable in production).
- `req.token` (decoded payload) and `req.thumbprint` (device key thumbprint) are attached on success.
- `optionalDPoPAuth(options)` continues without auth when no token is present.
- `requireDevice(thumbprint)` restricts a route to a single device; `requireUser(id)` to a single user.

### 2. Login endpoint (issuing tokens)

```ts
import { createDPoPAuth } from 'dpop-auth';

const auth = createDPoPAuth(process.env.DPOP_SECRET!, {
  algorithm: 'ES256',
  expiresIn: 300,
  enableFingerprinting: true,
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password, devicePublicKey, fingerprint } = req.body;
  // verify credentials with your own user store first
  const flow = await auth.createAuthFlow(username, devicePublicKey, fingerprint);
  // flow = { accessToken (JWT), refreshToken, expiresIn }
  res.json({ accessToken: flow.accessToken, refreshToken: flow.refreshToken });
});
```

`DPoPAuth.createAuthFlow()` issues the bound token pair. `auth.refreshAccessToken(refreshToken, devicePublicKeyJwk, fingerprint)` renews access tokens — the refresh token is bound to the same device key (7-day expiry).

### 3. Browser client

```ts
// once, at login: generate key pair, keep private key locally (IndexedDB/localStorage)
const kp = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
);
const publicKeyJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);

// per request: build and attach the proof
const proof = await createDPoPProof(method, url, privateKey, publicKeyJwk, {
  accessToken,          // adds the ath claim
  fingerprint,          // adds fph when fingerprinting enabled
});

await fetch(url, { headers: {
  'Authorization': `DPoP ${accessToken}`,
  'DPoP': proof,
}});
```

A worked browser example exists at `examples/client-side.html`; a server example at `examples/basic-usage.js`.

### 4. Production replay protection (Redis)

`MemoryReplayStore` is in-process only — with multiple instances behind a load balancer, a proof seen by instance A can be replayed to instance B. Use the Redis-backed store:

```ts
import { RedisReplayStore } from 'dpop-auth/dist/stores/redis';
// or from source: import { RedisReplayStore } from './stores/redis';

replayStore: new RedisReplayStore(redisClient, { keyPrefix: 'dpop:replay:', maxAge: 300 })
```

`RedisRevocationStore` and `RedisNonceStore` also exist in `src/stores/redis.ts`.

## Public API surface (from `src/index.ts`)

- **Middleware**: `dpopAuth`, `optionalDPoPAuth`, `requireDevice`, `requireUser`, `cleanupReplayStore`
- **Proofs**: `createDPoPProof`, `verifyDPoPProof`, `extractPublicKeyFromDPoP`, `extractThumbprintFromDPoP`, `validateDPoPFormat`
- **Tokens**: `createAccessToken`, `createRefreshToken`, `verifyAccessToken`, `verifyRefreshToken`, `extractThumbprintFromToken`, `isTokenExpired`
- **Keys / crypto**: `generateDPoPKeyPair`, `importDPoPKey`, `getKeyThumbprint`, `generateJTI`, `generateSecureRandom`, `createAccessTokenHash`, `generateFingerprintHash`, `validateFingerprintComponents`, `compareFingerprintHashes`, `validateTimestamp`, `createSecureHash`
- **Class**: `DPoPAuth` (default export) and factory `createDPoPAuth(secret, config)`
- **Types**: `DPoPConfig`, `MiddlewareOptions`, `DPoPPayload`, `AccessTokenPayload`, `ReplayStore`, `FingerprintComponents`, etc. (see `src/types/index.ts`)

## Gotchas (read before debugging)

1. **`htu` must match the actual request URI.** Proxies that rewrite paths, or a client that signs `http://` while the server sees `https://`, will fail with `DPOP_URI_MISMATCH`. Sign the exact URL the server sees.
2. **`jti` is single-use.** Retrying a request with the same proof (e.g. after a network error) is rejected as replay. Regenerate the proof per attempt.
3. **Clock skew**: proof `iat` must be within `clockTolerance` (default 60s). NTP-drifted servers cause `DPOP_TIMESTAMP_INVALID`.
4. **Secret strength**: production secrets should be >= 32 random characters; `validateSecretStrength` enforces this.
5. **Supported algorithms**: `ES256 | ES384 | ES512 | RS256 | PS256 | PS384 | PS512` (see `DPoPAlgorithm`). Key pair must match the algorithm (EC for ES*, RSA for RS/PS).
6. **Fingerprinting**: when `enableFingerprinting: true` (the default), the client's `fph` claim must match the hash the server computes from the same components — changing user-agent/locale mid-session can trigger `DPOP_FINGERPRINT_MISMATCH`.
7. **Error codes** follow `DPoPErrorCode` (e.g. `DPOP_2007` method mismatch, `DPOP_2010` replay detected). Catch `DPoPError` for structured handling; full list in `src/core/errors.ts`.

## Conventions

- TypeScript strict style; Prettier defaults; ESLint with `@typescript-eslint`.
- New features need tests — coverage thresholds (80%) fail CI otherwise.
- The landing page (`index.html`) is plain HTML/CSS, deployed to GitHub Pages by `.github/workflows/deploy-pages.yml` on pushes to `main` that touch it. No framework, no build step.
