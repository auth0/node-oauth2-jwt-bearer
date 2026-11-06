const fs = require("fs");
const path = require("path");

const pkgDir = path.join(__dirname, "packages/express-oauth2-jwt-bearer");

// Source links point at the release tag. `.version` holds the tag name
// (e.g. v1.11.0); ship writes it during the bump, before the postbump command
// runs `npm run docs`. `npm_package_version` can't be used here: the postbump
// runs from the workspace root, where it is the private root package's version.
// Regenerating between releases links to the last tag, so only commit the
// output from the release.
const gitRevision = fs.readFileSync(path.join(pkgDir, ".version"), "utf8").trim();
if (!/^v\d+\.\d+\.\d+/.test(gitRevision)) {
  throw new Error(`Unexpected release tag "${gitRevision}" in ${pkgDir}/.version`);
}

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
  gitRevision,

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
