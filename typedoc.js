module.exports = {
  out: "./docs/",
  excludePrivate: false,
  excludeExternals: false,
  hideGenerator: true,
  readme: "none",
  entryPoints: ["packages/express-oauth2-jwt-bearer/src"],
  tsconfig: "tsconfig.typedoc.json",
};
