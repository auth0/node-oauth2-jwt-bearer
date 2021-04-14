/* eslint-disable */
const fs = require('fs');
const path = require('path');
const { ResolverFactory } = require('enhanced-resolve');

module.exports = function enhancedResolve(modulePath, opts) {
  if (
    modulePath.startsWith('.') ||
    modulePath.startsWith(path.sep) ||
    modulePath.includes('access-token-jwt')
  ) {
    return opts.defaultResolver(modulePath, opts);
  }

  let wpResolver = ResolverFactory.createResolver({
    fileSystem: fs,
    useSyncFileSystemCalls: true,
    conditionNames: ['require'],
  });

  let result = wpResolver.resolveSync({}, opts.basedir, modulePath);

  if (result) {
    result = fs.realpathSync(result);
  }

  return result;
};
