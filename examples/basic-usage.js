/**
 * Basic usage example for dpop-auth package
 * 
 * This example demonstrates:
 * 1. Setting up DPoP authentication
 * 2. Creating device-bound tokens
 * 3. Using Express middleware
 * 4. Client-side integration
 */

const express = require('express');
const { 
  createDPoPAuth, 
  dpopAuth, 
  generateDPoPKeyPair,
  createAccessToken,
  createDPoPProof,
  generateFingerprintHash 
} = require('dpop-auth');

const app = express();
app.use(express.json());

// Initialize DPoP Auth with your secret
const SECRET_KEY = 'your-super-secret-key-change-this-in-production';
const dpopAuthInstance = createDPoPAuth(SECRET_KEY, {
  algorithm: 'ES256',
  expiresIn: 300, // 5 minutes
  enableFingerprinting: true,
});

// Example: User registration with device binding
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, publicKeyJwk, fingerprint } = req.body;
    
    // In a real app, you would:
    // 1. Validate email/password
    // 2. Hash password
    // 3. Store user in database
    // 4. Store device public key
    
    const userId = 'user123'; // From your user creation logic
    
    // Create authentication tokens bound to the device
    const authFlow = await dpopAuthInstance.createAuthFlow(
      userId,
      publicKeyJwk,
      fingerprint
    );
    
    res.json({
      message: 'Registration successful',
      user: { id: userId, email },
      accessToken: authFlow.accessToken.token,
      refreshToken: authFlow.refreshToken.token,
      expiresIn: authFlow.expiresIn,
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

// Example: Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken, publicKeyJwk, fingerprint } = req.body;
    
    // Refresh the access token
    const newAccessToken = await dpopAuthInstance.refreshAccessToken(
      refreshToken,
      publicKeyJwk,
      fingerprint
    );
    
    res.json({
      accessToken: newAccessToken.token,
      expiresIn: newAccessToken.expiresAt,
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Protected routes using DPoP middleware
app.use('/api/protected', dpopAuth({
  secret: SECRET_KEY,
  algorithm: 'ES256',
  enableFingerprinting: true,
}));

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

// Example: Generate device keys (for testing)
app.get('/api/dev/generate-keys', async (req, res) => {
  try {
    const keyPair = await generateDPoPKeyPair();
    
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

// Example: Generate fingerprint (for testing)
app.post('/api/dev/generate-fingerprint', (req, res) => {
  try {
    const components = {
      userAgent: req.get('user-agent'),
      acceptLanguage: req.get('accept-language'),
      acceptEncoding: req.get('accept-encoding'),
      ...req.body, // Additional components from client
    };
    
    const fingerprint = generateFingerprintHash(components);
    
    res.json({
      fingerprint,
      components,
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
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📚 API Documentation:`);
  console.log(`   POST /api/auth/register - Register with device binding`);
  console.log(`   POST /api/auth/login - Login with device binding`);
  console.log(`   POST /api/auth/refresh - Refresh access token`);
  console.log(`   GET  /api/protected/profile - Get user profile (protected)`);
  console.log(`   GET  /api/protected/data - Get secure data (protected)`);
  console.log(`   GET  /api/dev/generate-keys - Generate device keys (dev only)`);
  console.log(`   POST /api/dev/generate-fingerprint - Generate fingerprint (dev only)`);
});

module.exports = app;
