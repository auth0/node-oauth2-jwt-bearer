# Release Notes for GitHub Issue #147

## Feature: Configurable Token Locations

This release adds a new feature that allows users to specify which locations to check for JWT tokens (header, query parameters, or request body) rather than automatically checking all three locations.

### Changes Made:

1. Added a `TokenLocation` enum in `oauth2-bearer/src/get-token.ts` with values:
   - `HEADER` - For tokens in the Authorization header
   - `QUERY` - For tokens in query parameters
   - `BODY` - For tokens in the request body

2. Added a `GetTokenOptions` interface with options:
   - `checkHeader` - Whether to check for tokens in the Authorization header (default: true)
   - `checkQuery` - Whether to check for tokens in the query parameters (default: true)
   - `checkBody` - Whether to check for tokens in the request body (default: true)

3. Modified the `getToken` function to respect these options.

4. Added token location options to the `AuthOptions` interface in `express-oauth2-jwt-bearer/src/index.ts`:
   - `checkHeaderToken` - Whether to check for tokens in the Authorization header (default: true)
   - `checkQueryToken` - Whether to check for tokens in the query parameters (default: true)
   - `checkBodyToken` - Whether to check for tokens in the request body (default: true)
   - `tokenLocation` - A more convenient way to specify token locations using the `TokenLocation` enum

5. Updated documentation in README.md and EXAMPLES.md to explain how to use the new options.

### Publishing Steps:

1. Increment the version numbers in the package.json files of affected packages:
   - `packages/oauth2-bearer/package.json`
   - `packages/express-oauth2-jwt-bearer/package.json`

2. Run tests to ensure everything works correctly:
   ```
   npm test
   ```

3. Build the packages:
   ```
   npm run build
   ```

4. Publish to npm:
   ```
   npm publish
   ```

5. Update the documentation website to reflect the new options.

6. Create a GitHub release with these release notes.

### Usage Examples:

```js
// Only accept tokens from the Authorization header
app.use(auth({
  checkHeaderToken: true,
  checkQueryToken: false,
  checkBodyToken: false
}));

// Alternative using TokenLocation enum
app.use(auth({
  tokenLocation: TokenLocation.HEADER
}));

// Accept tokens from both header and query
app.use(auth({
  tokenLocation: [TokenLocation.HEADER, TokenLocation.QUERY]
}));
```

This feature allows users to improve security by restricting where tokens are accepted from, following security best practices that recommend using only the Authorization header for tokens in production environments.
