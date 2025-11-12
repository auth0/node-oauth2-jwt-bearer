module.exports = {
  preset: 'ts-jest/presets/js-with-ts',
  reporters: [
    'default',
    [
      'jest-junit',
      {
        suiteName: 'access-token-jwt',
        outputDirectory: '../../test-results/access-token-jwt',
      },
    ],
  ],
  testEnvironment: 'node',
  collectCoverageFrom: ['src/*'],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  moduleNameMapper: {
    '^@internal/oauth2-bearer-utils$': '<rootDir>/../oauth2-bearer/src/',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: {
          baseUrl: '.',
          paths: {
            '@internal/oauth2-bearer-utils': ['../oauth2-bearer/src'],
          },
        },
      },
    ],
  },
};
