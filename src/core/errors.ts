/**
 * DPoP Auth Error Codes
 * Comprehensive error codes for better debugging and handling
 */
export enum DPoPErrorCode {
    // Authentication Errors (1xxx)
    AUTH_MISSING_HEADER = 'DPOP_1001',
    AUTH_INVALID_FORMAT = 'DPOP_1002',
    AUTH_EMPTY_TOKEN = 'DPOP_1003',
    AUTH_TOKEN_EXPIRED = 'DPOP_1004',
    AUTH_TOKEN_INVALID = 'DPOP_1005',
    AUTH_TOKEN_REVOKED = 'DPOP_1006',

    // DPoP Proof Errors (2xxx)
    DPOP_MISSING_HEADER = 'DPOP_2001',
    DPOP_INVALID_FORMAT = 'DPOP_2002',
    DPOP_INVALID_TYPE = 'DPOP_2003',
    DPOP_MISSING_KEY = 'DPOP_2004',
    DPOP_INVALID_SIGNATURE = 'DPOP_2005',
    DPOP_MISSING_CLAIMS = 'DPOP_2006',
    DPOP_METHOD_MISMATCH = 'DPOP_2007',
    DPOP_URI_MISMATCH = 'DPOP_2008',
    DPOP_TIMESTAMP_INVALID = 'DPOP_2009',
    DPOP_REPLAY_DETECTED = 'DPOP_2010',
    DPOP_ATH_MISMATCH = 'DPOP_2011',
    DPOP_FINGERPRINT_MISMATCH = 'DPOP_2012',
    DPOP_NONCE_INVALID = 'DPOP_2013',

    // Device Binding Errors (3xxx)
    DEVICE_KEY_MISMATCH = 'DPOP_3001',
    DEVICE_NOT_AUTHORIZED = 'DPOP_3002',
    DEVICE_BINDINGS_LIMIT = 'DPOP_3003',
    DEVICE_ROTATION_REQUIRED = 'DPOP_3004',

    // Fingerprint Errors (4xxx)
    FINGERPRINT_INVALID = 'DPOP_4001',
    FINGERPRINT_BOT_DETECTED = 'DPOP_4002',
    FINGERPRINT_MISMATCH = 'DPOP_4003',

    // Key Errors (5xxx)
    KEY_GENERATION_FAILED = 'DPOP_5001',
    KEY_IMPORT_FAILED = 'DPOP_5002',
    KEY_INVALID_ALGORITHM = 'DPOP_5003',
    KEY_ROTATION_REQUIRED = 'DPOP_5004',

    // Configuration Errors (6xxx)
    CONFIG_MISSING_SECRET = 'DPOP_6001',
    CONFIG_INVALID_ALGORITHM = 'DPOP_6002',
    CONFIG_INVALID_EXPIRATION = 'DPOP_6003',

    // Rate Limiting Errors (7xxx)
    RATE_LIMIT_EXCEEDED = 'DPOP_7001',
    RATE_LIMIT_TOKEN_REQUESTS = 'DPOP_7002',
    RATE_LIMIT_PROOF_REQUESTS = 'DPOP_7003',

    // Internal Errors (9xxx)
    INTERNAL_ERROR = 'DPOP_9001',
    CRYPTO_ERROR = 'DPOP_9002',
    STORE_ERROR = 'DPOP_9003',
}

/**
 * Custom DPoP Error class with detailed information
 */
export class DPoPError extends Error {
    public readonly code: DPoPErrorCode;
    public readonly statusCode: number;
    public readonly timestamp: number;
    public readonly details: Record<string, any> | undefined;

    constructor(
        code: DPoPErrorCode,
        message: string,
        statusCode: number = 401,
        details?: Record<string, any>
    ) {
        super(message);
        this.name = 'DPoPError';
        this.code = code;
        this.statusCode = statusCode;
        this.timestamp = Date.now();
        this.details = details;

        // Maintains proper stack trace for where our error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, DPoPError);
        }
    }

    toJSON() {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            statusCode: this.statusCode,
            timestamp: this.timestamp,
            details: this.details,
        };
    }
}

/**
 * Error factory functions for common scenarios
 */
export const Errors = {
    missingAuthHeader: () => new DPoPError(
        DPoPErrorCode.AUTH_MISSING_HEADER,
        'Authorization header is required',
        401
    ),

    invalidAuthFormat: () => new DPoPError(
        DPoPErrorCode.AUTH_INVALID_FORMAT,
        'Authorization header must be in format: DPoP <token> or Bearer <token>',
        401
    ),

    emptyToken: () => new DPoPError(
        DPoPErrorCode.AUTH_EMPTY_TOKEN,
        'Access token is empty',
        401
    ),

    tokenExpired: () => new DPoPError(
        DPoPErrorCode.AUTH_TOKEN_EXPIRED,
        'Access token has expired',
        401
    ),

    tokenInvalid: (reason?: string) => new DPoPError(
        DPoPErrorCode.AUTH_TOKEN_INVALID,
        `Invalid access token${reason ? `: ${reason}` : ''}`,
        401
    ),

    tokenRevoked: () => new DPoPError(
        DPoPErrorCode.AUTH_TOKEN_REVOKED,
        'Access token has been revoked',
        401
    ),

    missingDPoPHeader: () => new DPoPError(
        DPoPErrorCode.DPOP_MISSING_HEADER,
        'DPoP header is required',
        401
    ),

    invalidDPoPType: () => new DPoPError(
        DPoPErrorCode.DPOP_INVALID_TYPE,
        'Invalid DPoP JWT type, expected dpop+jwt',
        401
    ),

    missingDPoPKey: () => new DPoPError(
        DPoPErrorCode.DPOP_MISSING_KEY,
        'Missing public key in DPoP JWT header',
        401
    ),

    invalidDPoPSignature: () => new DPoPError(
        DPoPErrorCode.DPOP_INVALID_SIGNATURE,
        'Invalid DPoP proof signature',
        401
    ),

    missingDPoPClaims: (claims?: string[]) => new DPoPError(
        DPoPErrorCode.DPOP_MISSING_CLAIMS,
        `Missing required DPoP claims${claims ? `: ${claims.join(', ')}` : ''}`,
        401
    ),

    methodMismatch: (expected: string, received: string) => new DPoPError(
        DPoPErrorCode.DPOP_METHOD_MISMATCH,
        `HTTP method mismatch: expected ${expected}, got ${received}`,
        401,
        { expected, received }
    ),

    uriMismatch: (expected: string, received: string) => new DPoPError(
        DPoPErrorCode.DPOP_URI_MISMATCH,
        `HTTP URI mismatch: expected ${expected}, got ${received}`,
        401,
        { expected, received }
    ),

    timestampInvalid: (difference: number, tolerance: number) => new DPoPError(
        DPoPErrorCode.DPOP_TIMESTAMP_INVALID,
        `Timestamp outside acceptable range. Difference: ${difference}s, tolerance: ${tolerance}s`,
        401,
        { difference, tolerance }
    ),

    replayDetected: () => new DPoPError(
        DPoPErrorCode.DPOP_REPLAY_DETECTED,
        'DPoP proof replay detected - this proof has already been used',
        401
    ),

    athMismatch: () => new DPoPError(
        DPoPErrorCode.DPOP_ATH_MISMATCH,
        'Access token hash mismatch in DPoP proof',
        401
    ),

    fingerprintMismatch: () => new DPoPError(
        DPoPErrorCode.DPOP_FINGERPRINT_MISMATCH,
        'Fingerprint mismatch between token and DPoP proof',
        401
    ),

    nonceInvalid: () => new DPoPError(
        DPoPErrorCode.DPOP_NONCE_INVALID,
        'Invalid or expired DPoP nonce',
        401
    ),

    deviceKeyMismatch: () => new DPoPError(
        DPoPErrorCode.DEVICE_KEY_MISMATCH,
        'Device key mismatch between token and DPoP proof',
        401
    ),

    deviceNotAuthorized: () => new DPoPError(
        DPoPErrorCode.DEVICE_NOT_AUTHORIZED,
        'This device is not authorized',
        403
    ),

    deviceBindingsLimit: (limit: number) => new DPoPError(
        DPoPErrorCode.DEVICE_BINDINGS_LIMIT,
        `Maximum device bindings limit reached (${limit})`,
        403,
        { limit }
    ),

    botDetected: () => new DPoPError(
        DPoPErrorCode.FINGERPRINT_BOT_DETECTED,
        'Automated client detected',
        403
    ),

    rateLimitExceeded: (retryAfter?: number) => new DPoPError(
        DPoPErrorCode.RATE_LIMIT_EXCEEDED,
        'Rate limit exceeded, please try again later',
        429,
        { retryAfter }
    ),

    configMissingSecret: () => new DPoPError(
        DPoPErrorCode.CONFIG_MISSING_SECRET,
        'Secret is required for DPoP authentication',
        500
    ),

    keyGenerationFailed: (reason?: string) => new DPoPError(
        DPoPErrorCode.KEY_GENERATION_FAILED,
        `Failed to generate key pair${reason ? `: ${reason}` : ''}`,
        500
    ),

    keyImportFailed: (reason?: string) => new DPoPError(
        DPoPErrorCode.KEY_IMPORT_FAILED,
        `Failed to import key${reason ? `: ${reason}` : ''}`,
        500
    ),

    invalidAlgorithm: (algorithm: string) => new DPoPError(
        DPoPErrorCode.KEY_INVALID_ALGORITHM,
        `Unsupported algorithm: ${algorithm}`,
        400,
        { algorithm }
    ),

    internalError: (message?: string) => new DPoPError(
        DPoPErrorCode.INTERNAL_ERROR,
        message || 'An internal error occurred',
        500
    ),
};
