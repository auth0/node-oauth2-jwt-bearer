module.exports = {
  preset: 'ts-jest',
  roots: ['<rootDir>'],
  moduleDirectories: ['node_modules', '<module-directory>'],
  modulePaths: ['<path-of-module>'],
  reporters: [
    'default',
    [
      'jest-junit',
      {
        suiteName: 'oauth2-bearer',
        outputDirectory: '../../test-results/oauth2-bearer',
      },
    ],
  ],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
};
