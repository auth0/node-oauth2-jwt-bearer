module.exports = {
  preset: 'ts-jest',
  rootDir: '<rootDir>../../',
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
