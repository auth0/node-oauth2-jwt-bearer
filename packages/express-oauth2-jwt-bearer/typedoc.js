module.exports = {
  out: './docs/',
  excludePrivate: false,
  excludeExternals: false,
  hideGenerator: true,
  readme: 'none',
  gitRevision: process.env.npm_package_version,
  entryPoints: ['src', '../access-token-jwt/src'],
  toc: false,
};
