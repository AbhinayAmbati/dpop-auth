/**
 * LRU Cache implementation for caching cryptographic operations
 * Optimizes performance by avoiding repeated expensive calculations
 */

interface CacheEntry<T> {
    value: T;
    lastAccess: number;
    createdAt: number;
}

export class LRUCache<K, V> {
    private cache: Map<K, CacheEntry<V>>;
    private readonly maxSize: number;
    private readonly ttlMs: number;
    private hits: number = 0;
    private misses: number = 0;

    constructor(options: { maxSize?: number; ttlMs?: number } = {}) {
        this.maxSize = options.maxSize || 1000;
        this.ttlMs = options.ttlMs || 5 * 60 * 1000; // 5 minutes default
        this.cache = new Map();
    }

    get(key: K): V | undefined {
        const entry = this.cache.get(key);

        if (!entry) {
            this.misses++;
            return undefined;
        }

        // Check TTL
        if (Date.now() - entry.createdAt > this.ttlMs) {
            this.cache.delete(key);
            this.misses++;
            return undefined;
        }

        // Update last access and move to end (most recently used)
        entry.lastAccess = Date.now();
        this.cache.delete(key);
        this.cache.set(key, entry);

        this.hits++;
        return entry.value;
    }

    set(key: K, value: V): void {
        // Delete if exists (to update position)
        this.cache.delete(key);

        // Evict oldest entries if at capacity
        while (this.cache.size >= this.maxSize) {
            const oldestKey = this.cache.keys().next().value;
            if (oldestKey !== undefined) {
                this.cache.delete(oldestKey);
            } else {
                break;
            }
        }

        const now = Date.now();
        this.cache.set(key, {
            value,
            lastAccess: now,
            createdAt: now,
        });
    }

    has(key: K): boolean {
        const entry = this.cache.get(key);
        if (!entry) return false;

        // Check TTL
        if (Date.now() - entry.createdAt > this.ttlMs) {
            this.cache.delete(key);
            return false;
        }

        return true;
    }

    delete(key: K): boolean {
        return this.cache.delete(key);
    }

    clear(): void {
        this.cache.clear();
        this.hits = 0;
        this.misses = 0;
    }

    get size(): number {
        return this.cache.size;
    }

    /**
     * Get cache statistics
     */
    getStats(): {
        size: number;
        maxSize: number;
        hits: number;
        misses: number;
        hitRate: number;
    } {
        const total = this.hits + this.misses;
        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            hits: this.hits,
            misses: this.misses,
            hitRate: total > 0 ? this.hits / total : 0,
        };
    }

    /**
     * Clean up expired entries
     */
    cleanup(): number {
        const now = Date.now();
        let removed = 0;

        for (const [key, entry] of this.cache.entries()) {
            if (now - entry.createdAt > this.ttlMs) {
                this.cache.delete(key);
                removed++;
            }
        }

        return removed;
    }
}

/**
 * Global cache instances for different purposes
 */
export const thumbprintCache = new LRUCache<string, string>({
    maxSize: 10000,
    ttlMs: 30 * 60 * 1000, // 30 minutes
});

export const keyImportCache = new LRUCache<string, any>({
    maxSize: 1000,
    ttlMs: 10 * 60 * 1000, // 10 minutes
});

/**
 * Utility to create a cache key from JWK
 */
export function createJwkCacheKey(jwk: any): string {
    // Create a deterministic string from JWK for caching
    const keyParts: string[] = [];

    if (jwk.kty) keyParts.push(jwk.kty);
    if (jwk.crv) keyParts.push(jwk.crv);
    if (jwk.x) keyParts.push(jwk.x);
    if (jwk.y) keyParts.push(jwk.y);
    if (jwk.n) keyParts.push(jwk.n);
    if (jwk.e) keyParts.push(jwk.e);

    return keyParts.join(':');
}
