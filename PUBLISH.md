# 📦 Publishing Guide for dpop-auth

This guide explains how to build, test, and publish the dpop-auth npm package.

## 🔧 Prerequisites

1. **Node.js 16+** installed
2. **npm account** with publishing permissions
3. **Git repository** set up and configured

## 🏗️ Build Process

### 1. Install Dependencies

```bash
npm install
```

### 2. Run Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode (for development)
npm run test:watch
```

### 3. Lint and Format Code

```bash
# Check for linting errors
npm run lint

# Fix linting errors automatically
npm run lint:fix

# Format code with Prettier
npm run format
```

### 4. Build TypeScript

```bash
# Build the package
npm run build

# Build in watch mode (for development)
npm run dev
```

### 5. Verify Build

```bash
# Check that dist/ directory contains compiled files
ls -la dist/

# Verify package contents
npm pack --dry-run
```

## 🧪 Testing

### Unit Tests

```bash
# Run unit tests
npm test

# Run specific test file
npm test -- crypto.test.ts

# Run tests with verbose output
npm test -- --verbose
```

### Integration Tests

```bash
# Test with example server
cd examples/
node basic-usage.js

# In another terminal, test the API
curl -X GET http://localhost:3000/api/dev/generate-keys
```

### Manual Testing

1. **Start example server**:
   ```bash
   cd examples/
   node basic-usage.js
   ```

2. **Open client example**:
   ```bash
   # Serve the HTML file
   python -m http.server 8080
   # Open http://localhost:8080/client-side.html
   ```

3. **Test complete flow**:
   - Generate device keys
   - Register user
   - Login user
   - Access protected endpoints
   - Refresh token

## 📋 Pre-publish Checklist

- [ ] All tests pass (`npm test`)
- [ ] Code is linted and formatted (`npm run lint`, `npm run format`)
- [ ] TypeScript compiles without errors (`npm run build`)
- [ ] Package builds successfully (`npm pack --dry-run`)
- [ ] Version number is updated in `package.json`
- [ ] CHANGELOG.md is updated with new features/fixes
- [ ] README.md is up to date
- [ ] Examples work correctly
- [ ] Security audit passes (`npm audit`)

## 🚀 Publishing Steps

### 1. Version Management

```bash
# Patch version (bug fixes)
npm version patch

# Minor version (new features)
npm version minor

# Major version (breaking changes)
npm version major
```

### 2. Login to npm

```bash
npm login
```

### 3. Publish Package

```bash
# Dry run to check what will be published
npm publish --dry-run

# Publish to npm registry
npm publish

# Publish with specific tag (for beta releases)
npm publish --tag beta
```

### 4. Verify Publication

```bash
# Check package on npm
npm view dpop-auth

# Install and test in a new project
mkdir test-install
cd test-install
npm init -y
npm install dpop-auth
node -e "console.log(require('dpop-auth'))"
```

## 🏷️ Release Process

### 1. Create Release Branch

```bash
git checkout -b release/v1.0.0
```

### 2. Update Version and Changelog

```bash
# Update package.json version
npm version 1.0.0 --no-git-tag-version

# Update CHANGELOG.md with new features and fixes
```

### 3. Commit and Tag

```bash
git add .
git commit -m "Release v1.0.0"
git tag v1.0.0
```

### 4. Merge and Push

```bash
git checkout main
git merge release/v1.0.0
git push origin main
git push origin v1.0.0
```

### 5. Publish to npm

```bash
npm publish
```

### 6. Create GitHub Release

1. Go to GitHub repository
2. Click "Releases" → "Create a new release"
3. Select tag `v1.0.0`
4. Add release notes from CHANGELOG.md
5. Publish release

## 🔒 Security Considerations

### Before Publishing

1. **Audit Dependencies**:
   ```bash
   npm audit
   npm audit fix
   ```

2. **Check for Secrets**:
   ```bash
   # Make sure no secrets are in the code
   grep -r "secret\|password\|key" src/ --exclude-dir=node_modules
   ```

3. **Verify .gitignore**:
   ```bash
   # Ensure sensitive files are ignored
   cat .gitignore
   ```

4. **Test Security Features**:
   ```bash
   # Run security-focused tests
   npm test -- --grep "security"
   ```

## 📊 Package Analytics

### Monitor Package Usage

```bash
# Check download stats
npm view dpop-auth

# Check package info
npm info dpop-auth
```

### Update Dependencies

```bash
# Check for outdated dependencies
npm outdated

# Update dependencies
npm update

# Check for security vulnerabilities
npm audit
```

## 🐛 Troubleshooting

### Common Issues

1. **TypeScript compilation errors**:
   ```bash
   # Clean build directory
   rm -rf dist/
   npm run build
   ```

2. **Test failures**:
   ```bash
   # Run tests with more verbose output
   npm test -- --verbose --no-cache
   ```

3. **Publishing permission errors**:
   ```bash
   # Check npm login status
   npm whoami
   
   # Re-login if needed
   npm logout
   npm login
   ```

4. **Package size too large**:
   ```bash
   # Check what's included in package
   npm pack --dry-run
   
   # Update .npmignore if needed
   ```

## 📈 Post-publish Tasks

1. **Update Documentation**:
   - Update README.md with new features
   - Update examples if API changed
   - Update TypeScript definitions

2. **Announce Release**:
   - Create GitHub release notes
   - Update project documentation
   - Notify users of breaking changes

3. **Monitor Issues**:
   - Watch for GitHub issues
   - Monitor npm download stats
   - Check for security vulnerabilities

## 🔄 Maintenance

### Regular Tasks

- **Weekly**: Check for security updates (`npm audit`)
- **Monthly**: Update dependencies (`npm update`)
- **Quarterly**: Review and update documentation
- **As needed**: Respond to issues and pull requests

### Long-term Maintenance

- Keep up with Node.js LTS releases
- Update TypeScript and other dev dependencies
- Review and update security practices
- Consider performance improvements
- Plan for major version updates

---

**Happy Publishing! 🚀**
