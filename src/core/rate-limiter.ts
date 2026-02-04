/**
 * Rate limiting utilities for DPoP authentication
 * Provides protection against brute force and denial of service attacks
 */

import { DPoPErrorCode } from './errors';

/**
 * Rate limiter configuration
 */
export interface RateLimiterConfig {
    /** Maximum requests allowed within the window */
    maxRequests: number;
    /** Time window in milliseconds */
    windowMs: number;
    /** Key prefix for storage */
    keyPrefix?: string;
    /** Skip rate limiting for successful requests */
    skipSuccessfulRequests?: boolean;
    /** Skip rate limiting for failed requests */
    skipFailedRequests?: boolean;
    /** Standard headers according to draft-ietf-httpapi-ratelimit-headers-08 */
    standardHeaders?: boolean;
}

/**
 * Rate limiter result
 */
export interface RateLimiterResult {
    success: boolean;
    remaining: number;
    resetAt: number;
    total: number;
    retryAfterMs?: number;
}

/**
 * Simple in-memory sliding window rate limiter
 */
export class SlidingWindowRateLimiter {
    private store: Map<string, number[]>;
    private config: Required<RateLimiterConfig>;
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor(config: RateLimiterConfig) {
        this.config = {
            maxRequests: config.maxRequests,
            windowMs: config.windowMs,
            keyPrefix: config.keyPrefix || 'rl:',
            skipSuccessfulRequests: config.skipSuccessfulRequests || false,
            skipFailedRequests: config.skipFailedRequests || false,
            standardHeaders: config.standardHeaders ?? true,
        };
        this.store = new Map();

        // Cleanup old entries every minute
        if (typeof setInterval !== 'undefined') {
            this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
            if (this.cleanupInterval.unref) {
                this.cleanupInterval.unref();
            }
        }
    }

    /**
     * Check if a request is allowed
     */
    async check(key: string): Promise<RateLimiterResult> {
        const now = Date.now();
        const fullKey = `${this.config.keyPrefix}${key}`;
        const windowStart = now - this.config.windowMs;

        // Get current requests for this key
        let requests = this.store.get(fullKey) || [];

        // Filter out expired requests
        requests = requests.filter(timestamp => timestamp > windowStart);

        const remaining = Math.max(0, this.config.maxRequests - requests.length);
        const resetAt = now + this.config.windowMs;

        if (requests.length >= this.config.maxRequests) {
            // Find the oldest request and calculate retry after
            const oldestRequest = requests[0] || now;
            const retryAfterMs = oldestRequest + this.config.windowMs - now;

            return {
                success: false,
                remaining: 0,
                resetAt,
                total: this.config.maxRequests,
                retryAfterMs: Math.max(0, retryAfterMs),
            };
        }

        // Add current request
        requests.push(now);
        this.store.set(fullKey, requests);

        return {
            success: true,
            remaining: remaining - 1,
            resetAt,
            total: this.config.maxRequests,
        };
    }

    /**
     * Reset rate limit for a key
     */
    reset(key: string): void {
        const fullKey = `${this.config.keyPrefix}${key}`;
        this.store.delete(fullKey);
    }

    /**
     * Cleanup expired entries
     */
    cleanup(): void {
        const now = Date.now();
        const windowStart = now - this.config.windowMs;

        for (const [key, requests] of this.store.entries()) {
            const valid = requests.filter(timestamp => timestamp > windowStart);
            if (valid.length === 0) {
                this.store.delete(key);
            } else if (valid.length !== requests.length) {
                this.store.set(key, valid);
            }
        }
    }

    /**
     * Get current stats
     */
    getStats(): { keys: number; totalRequests: number } {
        let totalRequests = 0;
        for (const requests of this.store.values()) {
            totalRequests += requests.length;
        }
        return { keys: this.store.size, totalRequests };
    }

    /**
     * Stop cleanup interval
     */
    stop(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
    }
}

/**
 * Token bucket rate limiter for smoother rate limiting
 */
export class TokenBucketRateLimiter {
    private store: Map<string, { tokens: number; lastRefill: number }>;
    private config: {
        maxTokens: number;
        refillRate: number; // tokens per second
        refillAmount: number;
        keyPrefix: string;
    };
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor(config: {
        maxTokens: number;
        refillRate?: number;
        refillAmount?: number;
        keyPrefix?: string;
    }) {
        this.config = {
            maxTokens: config.maxTokens,
            refillRate: config.refillRate || 1,
            refillAmount: config.refillAmount || 1,
            keyPrefix: config.keyPrefix || 'tb:',
        };
        this.store = new Map();

        if (typeof setInterval !== 'undefined') {
            this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
            if (this.cleanupInterval.unref) {
                this.cleanupInterval.unref();
            }
        }
    }

    /**
     * Try to consume a token
     */
    async consume(key: string, tokens: number = 1): Promise<RateLimiterResult> {
        const now = Date.now();
        const fullKey = `${this.config.keyPrefix}${key}`;

        let bucket = this.store.get(fullKey);

        if (!bucket) {
            bucket = { tokens: this.config.maxTokens, lastRefill: now };
        } else {
            // Refill tokens based on time elapsed
            const elapsed = (now - bucket.lastRefill) / 1000;
            const refill = Math.floor(elapsed * this.config.refillRate) * this.config.refillAmount;

            bucket.tokens = Math.min(this.config.maxTokens, bucket.tokens + refill);
            bucket.lastRefill = now;
        }

        if (bucket.tokens < tokens) {
            // Calculate when tokens will be available
            const tokensNeeded = tokens - bucket.tokens;
            const secondsToWait = Math.ceil(tokensNeeded / (this.config.refillRate * this.config.refillAmount));

            this.store.set(fullKey, bucket);

            return {
                success: false,
                remaining: bucket.tokens,
                resetAt: now + secondsToWait * 1000,
                total: this.config.maxTokens,
                retryAfterMs: secondsToWait * 1000,
            };
        }

        bucket.tokens -= tokens;
        this.store.set(fullKey, bucket);

        return {
            success: true,
            remaining: bucket.tokens,
            resetAt: now + (this.config.maxTokens - bucket.tokens) / (this.config.refillRate * this.config.refillAmount) * 1000,
            total: this.config.maxTokens,
        };
    }

    reset(key: string): void {
        const fullKey = `${this.config.keyPrefix}${key}`;
        this.store.delete(fullKey);
    }

    cleanup(): void {
        const now = Date.now();
        const maxAge = (this.config.maxTokens / (this.config.refillRate * this.config.refillAmount)) * 1000 * 2;

        for (const [key, bucket] of this.store.entries()) {
            if (now - bucket.lastRefill > maxAge && bucket.tokens >= this.config.maxTokens) {
                this.store.delete(key);
            }
        }
    }

    stop(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
    }
}

/**
 * Create rate limiter middleware for Express
 */
export function createRateLimiterMiddleware(options: {
    limiter: SlidingWindowRateLimiter | TokenBucketRateLimiter;
    keyGenerator?: (req: any) => string;
    onLimit?: (req: any, res: any, result: RateLimiterResult) => void;
    standardHeaders?: boolean;
}) {
    const {
        limiter,
        keyGenerator = (req) => req.ip || req.connection?.remoteAddress || 'unknown',
        onLimit,
        standardHeaders = true,
    } = options;

    return async (req: any, res: any, next: any) => {
        const key = keyGenerator(req);

        let result: RateLimiterResult;
        if (limiter instanceof SlidingWindowRateLimiter) {
            result = await limiter.check(key);
        } else {
            result = await limiter.consume(key);
        }

        // Set rate limit headers
        if (standardHeaders) {
            res.setHeader('RateLimit-Limit', result.total);
            res.setHeader('RateLimit-Remaining', result.remaining);
            res.setHeader('RateLimit-Reset', Math.ceil(result.resetAt / 1000));
        }

        if (!result.success) {
            if (standardHeaders && result.retryAfterMs) {
                res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000));
            }

            if (onLimit) {
                return onLimit(req, res, result);
            }

            return res.status(429).json({
                error: 'Rate limit exceeded',
                code: DPoPErrorCode.RATE_LIMIT_EXCEEDED,
                retryAfter: result.retryAfterMs ? Math.ceil(result.retryAfterMs / 1000) : undefined,
            });
        }

        next();
    };
}
