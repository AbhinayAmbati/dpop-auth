import { JWK, KeyLike } from 'jose';

/**
 * Supported cryptographic algorithms for DPoP
 */
export type DPoPAlgorithm = 'ES256' | 'RS256';

/**
 * DPoP token configuration options
 */
export interface DPoPConfig {
  /** Algorithm to use for signing (default: ES256) */
  algorithm?: DPoPAlgorithm;
  /** Token expiration time in seconds (default: 300) */
  expiresIn?: number;
  /** Clock skew tolerance in seconds (default: 60) */
  clockTolerance?: number;
  /** Maximum age for replay protection in seconds (default: 300) */
  maxAge?: number;
  /** Enable fingerprint binding (default: true) */
  enableFingerprinting?: boolean;
  /** Custom issuer for tokens */
  issuer?: string;
  /** Custom audience for tokens */
  audience?: string;
}

/**
 * DPoP proof JWT header
 */
export interface DPoPHeader {
  typ: 'dpop+jwt';
  alg: DPoPAlgorithm;
  jwk: JWK;
}

/**
 * DPoP proof JWT payload
 */
export interface DPoPPayload {
  /** HTTP method */
  htm: string;
  /** HTTP URI */
  htu: string;
  /** Issued at timestamp */
  iat: number;
  /** JWT ID for replay protection */
  jti: string;
  /** Optional access token hash */
  ath?: string;
  /** Optional fingerprint hash */
  fph?: string;
  /** Index signature for JWT compatibility */
  [key: string]: any;
}

/**
 * Access token payload with device binding
 */
export interface AccessTokenPayload {
  /** Subject (user ID) */
  sub: string;
  /** Issued at timestamp */
  iat: number;
  /** Expiration timestamp */
  exp: number;
  /** JWT ID */
  jti: string;
  /** Issuer */
  iss?: string;
  /** Audience */
  aud?: string;
  /** Device key thumbprint */
  cnf: {
    jkt: string;
  };
  /** Optional fingerprint hash */
  fph?: string;
  /** Custom claims */
  [key: string]: any;
}

/**
 * Refresh token payload
 */
export interface RefreshTokenPayload {
  /** Subject (user ID) */
  sub: string;
  /** Issued at timestamp */
  iat: number;
  /** Expiration timestamp */
  exp: number;
  /** JWT ID */
  jti: string;
  /** Issuer */
  iss?: string;
  /** Audience */
  aud?: string;
  /** Token type */
  typ: 'refresh';
  /** Device key thumbprint */
  cnf: {
    jkt: string;
  };
  /** Optional fingerprint hash */
  fph?: string;
  /** Index signature for JWT compatibility */
  [key: string]: any;
}

/**
 * Token creation result
 */
export interface TokenResult {
  /** The generated token */
  token: string;
  /** Token expiration timestamp */
  expiresAt: number;
  /** JWT ID for tracking */
  jti: string;
}

/**
 * Complete authentication flow result
 */
export interface AuthFlowResult {
  /** Access token information */
  accessToken: TokenResult;
  /** Refresh token information */
  refreshToken: TokenResult;
  /** Token expiration time in seconds */
  expiresIn: number;
  /** Token type (always 'DPoP') */
  tokenType: 'DPoP';
}

/**
 * DPoP proof verification result
 */
export interface DPoPVerificationResult {
  /** Whether the proof is valid */
  valid: boolean;
  /** Decoded payload if valid */
  payload?: DPoPPayload;
  /** Error message if invalid */
  error?: string;
  /** Device key thumbprint */
  thumbprint?: string;
}

/**
 * Token verification result
 */
export interface TokenVerificationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** Decoded payload if valid */
  payload?: AccessTokenPayload | RefreshTokenPayload;
  /** Error message if invalid */
  error?: string;
}

/**
 * Fingerprint components for device identification
 */
export interface FingerprintComponents {
  /** User agent string */
  userAgent?: string | undefined;
  /** Accept language header */
  acceptLanguage?: string | undefined;
  /** Accept encoding header */
  acceptEncoding?: string | undefined;
  /** Screen resolution */
  screenResolution?: string | undefined;
  /** Timezone offset */
  timezoneOffset?: number | undefined;
  /** Platform information */
  platform?: string | undefined;
  /** Additional custom components */
  [key: string]: any;
}

/**
 * Replay protection store interface
 */
export interface ReplayStore {
  /** Store a JTI with expiration */
  set(jti: string, expiresAt: number): Promise<void>;
  /** Check if JTI exists */
  has(jti: string): Promise<boolean>;
  /** Clean up expired JTIs */
  cleanup(): Promise<void>;
}

/**
 * Express middleware options
 */
export interface MiddlewareOptions extends DPoPConfig {
  /** Secret key for token verification */
  secret: string | KeyLike;
  /** Replay protection store */
  replayStore?: ReplayStore;
  /** Skip DPoP validation (for testing) */
  skipDPoP?: boolean;
  /** Custom error handler */
  onError?: (error: Error, req: any, res: any, next: any) => void;
}

/**
 * Key pair generation options
 */
export interface KeyPairOptions {
  /** Algorithm to use */
  algorithm?: DPoPAlgorithm;
  /** Key size for RSA (default: 2048) */
  keySize?: number;
  /** Curve for EC keys (default: P-256) */
  curve?: string;
}

/**
 * Extended Express Request with DPoP information
 */
export interface DPoPRequest {
  /** Verified access token payload */
  token?: AccessTokenPayload;
  /** DPoP proof payload */
  dpop?: DPoPPayload;
  /** Device fingerprint hash */
  fingerprint?: string;
  /** Device key thumbprint */
  thumbprint?: string;
}

/**
 * Simplified configuration for quick setup
 */
export interface SimpleDPoPConfig extends Partial<DPoPConfig> {
  /** Enable automatic fingerprinting (default: true) */
  autoFingerprint?: boolean;
  /** Custom token expiration in minutes (default: 5) */
  tokenExpirationMinutes?: number;
  /** Custom refresh token expiration in days (default: 7) */
  refreshExpirationDays?: number;
}

/**
 * Device key pair result
 */
export interface DeviceKeyPair {
  /** Public key in JWK format */
  publicKey: any;
  /** Private key for signing */
  privateKey: any;
  /** Public key JWK */
  publicKeyJwk: any;
  /** Private key JWK */
  privateKeyJwk: any;
  /** Key thumbprint */
  thumbprint: string;
  /** Algorithm used */
  algorithm: DPoPAlgorithm;
}

/**
 * Client-side DPoP proof options
 */
export interface DPoPProofOptions {
  /** Access token to bind (optional) */
  accessToken?: string;
  /** Device fingerprint (optional) */
  fingerprint?: string;
  /** Algorithm to use */
  algorithm?: DPoPAlgorithm;
}

/**
 * Simplified auth setup result
 */
export interface SimpleDPoPAuthSetup {
  /** Main auth instance */
  auth: any; // Will be DPoPAuth but avoiding circular reference
  /** Pre-configured middleware */
  middleware: any;
  /** Device key generation function */
  generateDeviceKeys: () => Promise<DeviceKeyPair>;
  /** Auth flow creation function */
  createAuthFlow: (userId: string, deviceKey: any, fingerprint?: string) => Promise<AuthFlowResult>;
  /** Token refresh function */
  refreshToken: (refreshToken: string, deviceKey: any, fingerprint?: string) => Promise<TokenResult>;
}
