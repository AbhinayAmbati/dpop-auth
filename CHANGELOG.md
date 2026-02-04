# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-04

### Added

#### Security Enhancements
- **Rate Limiting** - Sliding window and token bucket rate limiters
- **Token Revocation** - Support for immediate token invalidation
- **Constant-Time Comparison** - Prevent timing attacks with `secureCompare()`
- **Secret Validation** - `validateSecretStrength()` for checking secret security
- **Request Signing** - `createRequestSignature()` and `verifyRequestSignature()`

#### Performance Improvements
- **LRU Caching** - Cache for JWK thumbprints and key imports
- **Optimized Crypto** - Reduced redundant cryptographic operations

#### New Features
- **Extended Algorithm Support** - ES384, ES512, PS256, PS384, PS512
- **Token Introspection** - `introspectToken()` for debugging
- **Token Rotation** - `TokenRotationManager` with grace period support
- **Token Lifetime** - `getTokenLifetime()` for expiration checking
- **Error Codes** - `DPoPErrorCode` enum for better error handling
- **Custom Error Class** - `DPoPError` with detailed context

#### Redis Stores (Production-Ready)
- `RedisReplayStore` - Distributed replay protection
- `RedisRevocationStore` - Distributed token revocation
- `RedisNonceStore` - Distributed nonce management
- `RedisDeviceRegistry` - Multi-device user tracking

#### Utilities
- `validateTokenStructure()` - JWT structure validation
- `sanitizeForLogging()` - Safe logging helper
- `maskSensitiveData()` - Data masking utility
- `validateJwkSecurity()` - JWK security checks
- `IPUtils` - IP address utilities

### Changed
- Minimum Node.js version is now 18.0.0
- `DPoPAuth` class now accepts `replayStore` and `revocationStore` options
- Improved TypeScript types with `exactOptionalPropertyTypes` support

### Fixed
- Type compatibility with strict TypeScript configurations
- Memory cleanup in stores with proper `stop()` methods

## [1.0.1] - 2025-12-01

### Fixed
- Minor bug fixes and documentation updates

## [1.0.0] - 2025-11-15

### Added
- Initial release
- DPoP key pair generation (ES256, RS256)
- Access and refresh token creation
- DPoP proof creation and verification
- Express middleware for authentication
- Device fingerprint binding
- Memory-based replay protection
- TypeScript support
