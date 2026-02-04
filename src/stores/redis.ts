/**
 * Redis-based stores for production deployments
 * Provides distributed replay protection and token revocation
 */

import type { ReplayStore } from '../types';

/**
 * Generic Redis client interface
 * Compatible with both 'redis' and 'ioredis' packages
 */
export interface RedisClient {
    set(key: string, value: string, options?: { EX?: number; PX?: number }): Promise<any>;
    get(key: string): Promise<string | null>;
    exists(key: string): Promise<number>;
    del(key: string | string[]): Promise<number>;
    keys(pattern: string): Promise<string[]>;
    expire(key: string, seconds: number): Promise<number>;
    sadd(key: string, ...members: string[]): Promise<number>;
    sismember(key: string, member: string): Promise<number>;
    srem(key: string, ...members: string[]): Promise<number>;
    smembers(key: string): Promise<string[]>;
}

/**
 * Configuration options for Redis stores
 */
export interface RedisStoreConfig {
    /** Redis client instance */
    client: RedisClient;
    /** Key prefix for namespacing (default: 'dpop:') */
    keyPrefix?: string;
    /** TTL for entries in seconds (default: 300) */
    ttlSeconds?: number;
}

/**
 * Redis-based replay protection store
 * Suitable for distributed systems and production use
 */
export class RedisReplayStore implements ReplayStore {
    private client: RedisClient;
    private keyPrefix: string;
    private ttlSeconds: number;

    constructor(config: RedisStoreConfig) {
        this.client = config.client;
        this.keyPrefix = config.keyPrefix || 'dpop:replay:';
        this.ttlSeconds = config.ttlSeconds || 300;
    }

    async set(jti: string, expiresAt: number): Promise<void> {
        const key = `${this.keyPrefix}${jti}`;
        // Use provided expiration or fallback to configured TTL
        const ttlFromExpiration = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
        const ttl = Math.min(ttlFromExpiration, this.ttlSeconds);
        await this.client.set(key, String(expiresAt), { EX: ttl });
    }

    async has(jti: string): Promise<boolean> {
        const key = `${this.keyPrefix}${jti}`;
        const exists = await this.client.exists(key);
        return exists > 0;
    }

    async cleanup(): Promise<void> {
        // Redis handles TTL automatically, but we can force cleanup if needed
        // This is mainly for interface compliance
    }

    /**
     * Get store statistics
     */
    async getStats(): Promise<{ count: number }> {
        const keys = await this.client.keys(`${this.keyPrefix}*`);
        return { count: keys.length };
    }
}

/**
 * Redis-based token revocation store
 * For storing revoked tokens until their natural expiration
 */
export class RedisRevocationStore {
    private client: RedisClient;
    private keyPrefix: string;
    private maxTtlSeconds: number;

    constructor(config: RedisStoreConfig & { maxTtlSeconds?: number }) {
        this.client = config.client;
        this.keyPrefix = config.keyPrefix || 'dpop:revoked:';
        this.maxTtlSeconds = config.maxTtlSeconds || 7 * 24 * 60 * 60; // 7 days default
    }

    /**
     * Revoke a token by its JTI
     */
    async revoke(jti: string, tokenExp?: number): Promise<void> {
        const key = `${this.keyPrefix}${jti}`;

        // Calculate TTL based on token expiration or use max TTL
        let ttl = this.maxTtlSeconds;
        if (tokenExp) {
            const remaining = Math.ceil((tokenExp * 1000 - Date.now()) / 1000);
            ttl = Math.max(1, Math.min(remaining, this.maxTtlSeconds));
        }

        await this.client.set(key, String(Date.now()), { EX: ttl });
    }

    /**
     * Check if a token is revoked
     */
    async isRevoked(jti: string): Promise<boolean> {
        const key = `${this.keyPrefix}${jti}`;
        const exists = await this.client.exists(key);
        return exists > 0;
    }

    /**
     * Revoke all tokens for a user
     */
    async revokeAllForUser(_userId: string, tokenJtis: string[]): Promise<void> {
        const promises = tokenJtis.map(jti => this.revoke(jti));
        await Promise.all(promises);
    }
}

/**
 * Redis-based nonce store for additional replay protection
 */
export class RedisNonceStore {
    private client: RedisClient;
    private keyPrefix: string;
    private ttlSeconds: number;

    constructor(config: RedisStoreConfig) {
        this.client = config.client;
        this.keyPrefix = config.keyPrefix || 'dpop:nonce:';
        this.ttlSeconds = config.ttlSeconds || 120; // 2 minutes default
    }

    /**
     * Generate and store a new nonce
     */
    async generate(): Promise<string> {
        const { randomBytes } = await import('node:crypto');
        const nonce = randomBytes(16).toString('base64url');
        const key = `${this.keyPrefix}${nonce}`;

        await this.client.set(key, '1', { EX: this.ttlSeconds });
        return nonce;
    }

    /**
     * Validate and consume a nonce (one-time use)
     */
    async validate(nonce: string): Promise<boolean> {
        const key = `${this.keyPrefix}${nonce}`;
        const exists = await this.client.exists(key);

        if (exists > 0) {
            await this.client.del(key); // Consume the nonce
            return true;
        }

        return false;
    }
}

/**
 * Redis-based device registry for tracking user devices
 */
export class RedisDeviceRegistry {
    private client: RedisClient;
    private keyPrefix: string;
    private maxDevicesPerUser: number;

    constructor(config: RedisStoreConfig & { maxDevicesPerUser?: number }) {
        this.client = config.client;
        this.keyPrefix = config.keyPrefix || 'dpop:devices:';
        this.maxDevicesPerUser = config.maxDevicesPerUser || 5;
    }

    /**
     * Register a device for a user
     */
    async registerDevice(userId: string, thumbprint: string, metadata?: Record<string, any>): Promise<boolean> {
        const key = `${this.keyPrefix}${userId}`;

        // Check current device count
        const devices = await this.client.smembers(key);
        if (devices.length >= this.maxDevicesPerUser && !devices.includes(thumbprint)) {
            return false; // Device limit reached
        }

        await this.client.sadd(key, thumbprint);

        // Store device metadata if provided
        if (metadata) {
            const metaKey = `${this.keyPrefix}meta:${userId}:${thumbprint}`;
            await this.client.set(metaKey, JSON.stringify(metadata));
        }

        return true;
    }

    /**
     * Check if a device is registered for a user
     */
    async isDeviceRegistered(userId: string, thumbprint: string): Promise<boolean> {
        const key = `${this.keyPrefix}${userId}`;
        const result = await this.client.sismember(key, thumbprint);
        return result > 0;
    }

    /**
     * Remove a device from a user
     */
    async removeDevice(userId: string, thumbprint: string): Promise<void> {
        const key = `${this.keyPrefix}${userId}`;
        await this.client.srem(key, thumbprint);

        const metaKey = `${this.keyPrefix}meta:${userId}:${thumbprint}`;
        await this.client.del(metaKey);
    }

    /**
     * Get all devices for a user
     */
    async getUserDevices(userId: string): Promise<string[]> {
        const key = `${this.keyPrefix}${userId}`;
        return this.client.smembers(key);
    }

    /**
     * Remove all devices for a user
     */
    async removeAllDevices(userId: string): Promise<void> {
        const devices = await this.getUserDevices(userId);
        const key = `${this.keyPrefix}${userId}`;

        await this.client.del(key);

        // Remove all device metadata
        const metaKeys = devices.map(d => `${this.keyPrefix}meta:${userId}:${d}`);
        if (metaKeys.length > 0) {
            await this.client.del(metaKeys);
        }
    }
}
