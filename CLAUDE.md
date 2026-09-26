# CLAUDE.md

This file gives Claude Code (and similar assistants) the essentials for working in this repository. **Read `AGENTS.md` for the full guide** — architecture, complete API surface, recipes and gotchas.

## What this is

`dpop-auth` — a Node.js/TypeScript library implementing DPoP (RFC 9449) device-bound, sender-constrained API tokens. Express middleware, per-request proof JWTs, anti-replay stores (memory + Redis), optional fingerprint binding. Single runtime dependency: `jose`. Node >= 16.

## Commands

```bash
npm run build            # tsc -> dist/
npm test                 # jest
npm run test:coverage    # enforced 80% threshold
npm run lint             # eslint
```

Run `npm run build && npm test` before considering any change to `src/` done.

## The 30-second mental model

1. Client generates an ES256 key pair in the browser; sends only the public JWK at login.
2. Server issues tokens carrying the key thumbprint (`cnf.jkt`) + optional fingerprint (`fph`).
3. Every request is signed into a short-lived proof JWT (`typ: dpop+jwt`) bound to `htm`, `htu`, `iat`, single-use `jti`, and the access-token hash `ath`.
4. `dpopAuth()` middleware verifies token + proof + binding + freshness + replay-store uniqueness, then attaches `req.token` and `req.thumbprint`.

## Most common integration (server)

```ts
import { dpopAuth, MemoryReplayStore } from 'dpop-auth';

app.use('/api/protected', dpopAuth({
  secret: process.env.DPOP_SECRET,   // >= 32 random chars in production
  replayStore: new MemoryReplayStore(),
}));
// use RedisReplayStore (src/stores/redis.ts) when running multiple instances
```

`DPoPAuth` class / `createDPoPAuth(secret, config)` handle the full flow: `createAuthFlow()`, `refreshAccessToken()`, `getMiddleware()`.

## Things Claude should not get wrong

- The middleware accepts `DPoP` and `Bearer` Authorization schemes, but the DPoP proof header is always required (unless `skipDPoP` — testing only).
- `htu` in the proof must match the exact request URI the server sees; `jti` is single-use — regenerate proofs on retry, never reuse.
- Default config: `ES256`, `expiresIn` 300s, `clockTolerance` 60s, `enableFingerprinting` true.
- Tests must keep coverage >= 80% (branches/functions/lines/statements).
- `index.html` is the no-framework landing page, auto-deployed to GitHub Pages on push to `main`.
