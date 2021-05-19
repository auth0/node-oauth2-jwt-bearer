const fs = require('fs');
const { ResolverFactory } = require('enhanced-resolve');

// Use a special resolver for jose as it uses named and conditional exports which aren't
// supported by the default jest resolver yet facebook/jest#9771
module.exports = function enhancedResolve(modulePath, opts) {
  if (!modulePath.startsWith('jose-node-cjs-runtime/')) {
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
