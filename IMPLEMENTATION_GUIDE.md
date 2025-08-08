# Implementation Guide for Token Location Configuration Feature (Issue #147)

## Overview

This guide outlines the steps to complete the implementation of the token location configuration feature, which allows users to specify which locations to check for JWT tokens (header, query parameters, or request body) rather than automatically checking all three locations.

## Implementation Steps Completed

1. ✅ Added `TokenLocation` enum in `oauth2-bearer/src/get-token.ts`
2. ✅ Added `GetTokenOptions` interface in `oauth2-bearer/src/get-token.ts`
3. ✅ Modified `getToken` function to accept options parameter
4. ✅ Added token location options to `AuthOptions` interface in `express-oauth2-jwt-bearer/src/index.ts`
5. ✅ Updated middleware implementation to pass options to `getToken`
6. ✅ Added tests to verify token location functionality
7. ✅ Updated documentation in README.md with token location options
8. ✅ Updated EXAMPLES.md with token location configuration examples
9. ✅ Updated package versions

## Remaining Steps to Complete

### 1. Build and Test the Changes

Run the following commands from the root directory:

```zsh
# Install dependencies if needed
npm install

# Run tests to ensure everything works
npm test

# Build the packages
npm run build
```

### 2. Generate Updated TypeDoc Documentation

The documentation website needs to be updated to reflect the new token location options:

```zsh
# Generate updated documentation
npm run docs
```

### 3. Create a Pull Request

Ensure your branch includes all the changes and create a pull request:

```zsh
# If you haven't created a branch yet
git checkout -b feature/configurable-token-locations

# Add all changed files
git add .

# Commit changes
git commit -m "Add support for configurable token locations (Issue #147)"

# Push changes to remote repository
git push origin feature/configurable-token-locations
```

### 4. Publishing the Packages

Once the PR is approved and merged, follow these steps to publish the packages:

```zsh
# Switch to main branch and pull the latest changes
git checkout main
git pull

# Log in to npm if needed
npm login

# Publish the packages
npm publish --workspaces --access public
```

### 5. Create a GitHub Release

Create a new release on GitHub:

1. Go to the GitHub repository
2. Click on "Releases"
3. Click "Draft a new release"
4. Create a tag `v1.7.0`
5. Use "v1.7.0 - Configurable Token Locations" as the title
6. Add the release notes from RELEASE_NOTES.md
7. Publish the release

## Testing the Published Packages

To verify the published packages work as expected, you can create a test project:

```zsh
# Create a test directory
mkdir test-token-locations
cd test-token-locations

# Initialize a new project
npm init -y

# Install the published packages
npm install express express-oauth2-jwt-bearer

# Create a test file (app.js)
cat > app.js << 'EOL'
const express = require('express');
const { auth, TokenLocation } = require('express-oauth2-jwt-bearer');

const app = express();

// Example 1: Only accept tokens from the Authorization header
app.get('/secure-header', auth({
  tokenLocation: TokenLocation.HEADER,
  // Mock values for testing
  issuer: 'https://example.auth0.com/',
  audience: 'https://api.example.com/',
  secret: 'your-secret'
}), (req, res) => {
  res.json({ message: 'Token from header accepted!' });
});

// Example 2: Accept tokens from query or header
app.get('/secure-query-header', auth({
  tokenLocation: [TokenLocation.HEADER, TokenLocation.QUERY],
  // Mock values for testing
  issuer: 'https://example.auth0.com/',
  audience: 'https://api.example.com/',
  secret: 'your-secret'
}), (req, res) => {
  res.json({ message: 'Token from header or query accepted!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
EOL

# Run the test application
node app.js
```

## Documentation Update

The updated documentation website should now include the new token location options in the `AuthOptions` interface documentation, as well as examples of how to use them.
