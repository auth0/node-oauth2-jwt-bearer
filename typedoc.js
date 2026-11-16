// Writes the HTML reference to docs/ (published with GitHub Pages) and the
// Mintlify artifact, which is committed for the docs content pipeline.
module.exports = {
  out: "./docs/",
  json: "./packages/express-oauth2-jwt-bearer/mintlify/express-oauth2-jwt-bearer.json",
  excludePrivate: false,
  excludeExternals: false,
  hideGenerator: true,
  readme: "none",
  entryPoints: ["packages/express-oauth2-jwt-bearer/src"],
  tsconfig: "tsconfig.typedoc.json",
  gitRevision: "main",

  categorizeByGroup: false,
  categoryOrder: [
    "Getting Started",
    "Configuration",
    "Claim & Scope Checks",
    "DPoP & mTLS",
    "Multiple Issuers",
    "Errors",
    "*",
    "Other",
  ],
  defaultCategory: "Other",
  navigation: {
    includeCategories: true,
    includeGroups: false,
  },
  sort: ["kind", "alphabetical"],
  kindSortOrder: ["Function", "Variable", "Class", "Interface", "TypeAlias", "Enum"],
};
