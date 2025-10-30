/**
 * Basic usage example for dpop-auth package v1.1.0
 * 
 * This example demonstrates the new simplified API:
 * 1. Quick setup with createSimpleDPoPAuth
 * 2. Streamlined device-bound tokens
 * 3. Pre-configured Express middleware
 * 4. Improved client-side integration
 */

const express = require('express');
const { 
  createSimpleDPoPAuth,
  createDPoPAuth,
  generateDPoPKeyPair,
  generateFingerprintHash 
} = require('dpop-auth');

const app = express();
app.use(express.json());

// NEW: Quick setup with simplified API
const SECRET_KEY = 'your-super-secret-key-change-this-in-production';

// Option 1: Ultra-simple setup (recommended for most users)
const setupAuth = async () => {
  const { auth, middleware, generateDeviceKeys, createAuthFlow, refreshToken } = 
    await createSimpleDPoPAuth(SECRET_KEY, {
      expiresIn: 300, // 5 minutes
      enableFingerprinting: true,
    });
  
  return { auth, middleware, generateDeviceKeys, createAuthFlow, refreshToken };
};

// Option 2: Traditional setup (for advanced users)
const dpopAuthInstance = createDPoPAuth(SECRET_KEY, {
  algorithm: 'ES256',
  expiresIn: 300,
  enableFingerprinting: true,
});

// NEW: Simplified registration endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, publicKeyJwk, fingerprint } = req.body;
    
    // In a real app, you would:
    // 1. Validate email/password
    // 2. Hash password
    // 3. Store user in database
    // 4. Store device public key
    
    const userId = 'user123'; // From your user creation logic
    
    // NEW: Simplified auth flow creation
    const authFlow = await dpopAuthInstance.createAuthFlow(
      userId,
      publicKeyJwk,
      fingerprint
    );
    
    res.json({
      message: 'Registration successful',
      user: { id: userId, email },
      ...authFlow, // Contains accessToken, refreshToken, expiresIn, tokenType
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Example: User login with device binding
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, publicKeyJwk, fingerprint } = req.body;
    
    // In a real app, you would:
    // 1. Validate email/password against database
    // 2. Verify device public key matches stored key
    
    const userId = 'user123'; // From your authentication logic
    
    // Create new authentication tokens
    const authFlow = await dpopAuthInstance.createAuthFlow(
      userId,
      publicKeyJwk,
      fingerprint
    );
    
    res.json({
      message: 'Login successful',
      user: { id: userId, email },
      accessToken: authFlow.accessToken.token,
      refreshToken: authFlow.refreshToken.token,
      expiresIn: authFlow.expiresIn,
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// NEW: Simplified token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken, publicKeyJwk, fingerprint } = req.body;
    
    // NEW: Simplified refresh with better error handling
    const newAccessToken = await dpopAuthInstance.refreshAccessToken(
      refreshToken,
      publicKeyJwk,
      fingerprint
    );
    
    res.json({
      accessToken: newAccessToken.token,
      expiresAt: newAccessToken.expiresAt,
      jti: newAccessToken.jti,
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// NEW: Simplified middleware setup
app.use('/api/protected', dpopAuthInstance.middleware());

// Alternative: Use the ultra-simple setup
// setupAuth().then(({ middleware }) => {
//   app.use('/api/protected', middleware);
// });

// Example protected endpoint
app.get('/api/protected/profile', (req, res) => {
  // Access authenticated user information
  const userId = req.token.sub;
  const deviceThumbprint = req.thumbprint;
  const fingerprint = req.fingerprint;
  
  res.json({
    message: 'Protected data accessed successfully',
    user: {
      id: userId,
      deviceThumbprint,
      fingerprint,
    },
    timestamp: new Date().toISOString(),
  });
});

// Example protected endpoint with additional data
app.get('/api/protected/data', (req, res) => {
  res.json({
    data: [
      { id: 1, name: 'Secure Item 1' },
      { id: 2, name: 'Secure Item 2' },
      { id: 3, name: 'Secure Item 3' },
    ],
    user: req.token.sub,
    accessedAt: new Date().toISOString(),
  });
});

// NEW: Simplified device key generation
app.get('/api/dev/generate-keys', async (req, res) => {
  try {
    // NEW: Use the instance method for consistent algorithm
    const keyPair = await dpopAuthInstance.generateDeviceKeys();
    
    res.json({
      publicKeyJwk: keyPair.publicKeyJwk,
      privateKeyJwk: keyPair.privateKeyJwk, // Don't expose this in production!
      thumbprint: keyPair.thumbprint,
      algorithm: keyPair.algorithm,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NEW: Simplified fingerprint generation
app.post('/api/dev/generate-fingerprint', (req, res) => {
  try {
    const components = {
      userAgent: req.get('user-agent'),
      acceptLanguage: req.get('accept-language'),
      acceptEncoding: req.get('accept-encoding'),
      ...req.body, // Additional components from client
    };
    
    // NEW: Use instance method for consistency
    const fingerprint = dpopAuthInstance.generateFingerprint(components);
    
    res.json({
      fingerprint,
      components,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NEW: Token verification endpoint
app.post('/api/dev/verify-token', async (req, res) => {
  try {
    const { token } = req.body;
    const result = await dpopAuthInstance.verifyToken(token);
    
    res.json({
      valid: result.valid,
      payload: result.payload,
      error: result.error,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message,
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 DPoP Auth v1.1.0 - Server running on port ${PORT}`);
  console.log(`📚 API Documentation:`);
  console.log(`   POST /api/auth/register - Register with device binding`);
  console.log(`   POST /api/auth/login - Login with device binding`);
  console.log(`   POST /api/auth/refresh - Refresh access token`);
  console.log(`   GET  /api/protected/profile - Get user profile (protected)`);
  console.log(`   GET  /api/protected/data - Get secure data (protected)`);
  console.log(`   GET  /api/dev/generate-keys - Generate device keys (dev only)`);
  console.log(`   POST /api/dev/generate-fingerprint - Generate fingerprint (dev only)`);
  console.log(`   POST /api/dev/verify-token - Verify token (dev only)`);
  console.log(`\n✨ New in v1.1.0:`);
  console.log(`   - Simplified API with createSimpleDPoPAuth()`);
  console.log(`   - Better TypeScript support`);
  console.log(`   - Modern ESM standards`);
  console.log(`   - Reduced boilerplate code`);
});

module.exports = app;

// NEW: Example of ultra-simple setup (commented out)
/*
const runSimpleExample = async () => {
  const { auth, middleware, generateDeviceKeys, createAuthFlow } = 
    await createSimpleDPoPAuth(SECRET_KEY);
  
  // Generate device keys
  const deviceKeys = await generateDeviceKeys();
  console.log('Generated device keys:', deviceKeys.thumbprint);
  
  // Create auth flow
  const authFlow = await createAuthFlow('user123', deviceKeys.publicKeyJwk);
  console.log('Created auth flow:', authFlow.tokenType);
};

// Uncomment to run the simple example
// runSimpleExample().catch(console.error);
*/
