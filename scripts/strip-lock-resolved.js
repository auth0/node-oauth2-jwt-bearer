#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const lockfilePath = path.resolve(__dirname, '..', 'package-lock.json');

// Open once in read+write mode — single path resolution, no TOCTOU window.
let fd;
try {
  fd = fs.openSync(lockfilePath, 'r+');
} catch (e) {
  if (e.code === 'ENOENT') process.exit(0);
  throw e;
}

try {
  const lock = JSON.parse(fs.readFileSync(fd, 'utf8'));

  // lockfile v2/v3 — flat packages map
  // Preserve resolved on link:true entries — these are workspace symlinks pointing
  // to local package paths, not registry URLs.
  if (lock.packages) {
    Object.values(lock.packages).forEach(pkg => {
      if (!pkg.link) delete pkg.resolved;
    });
  }

  // lockfile v1 — nested dependencies
  function stripDeps(deps) {
    if (!deps) return;
    Object.values(deps).forEach(dep => {
      delete dep.resolved;
      stripDeps(dep.dependencies);
    });
  }
  stripDeps(lock.dependencies);

  const output = JSON.stringify(lock, null, 2) + '\n';
  fs.ftruncateSync(fd, 0);
  fs.writeSync(fd, output, 0, 'utf8');
  console.log('Stripped resolved fields from package-lock.json');
} finally {
  fs.closeSync(fd);
}
