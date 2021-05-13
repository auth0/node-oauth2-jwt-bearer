module.exports = {
  out: './docs/',
  excludePrivate: false,
  excludeExternals: false,
  hideGenerator: true,
  readme: 'none',
  gitRevision: process.env.npm_package_version,
  entryPoints: ['src'],
  plugin: ['typedoc-plugin-markdown'],
  hidePageTitle: true,
  hideBreadcrumbs: true,
  allReflectionsHaveOwnDocument: true,
};
