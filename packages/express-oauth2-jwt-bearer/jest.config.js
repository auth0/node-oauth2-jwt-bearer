module.exports = {
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  collectCoverageFrom: ['src/*'],
  coverageThreshold: {
    global: {
      branches: 87,
      functions: 65,
      lines: 88,
      statements: 88,
    },
  },
  reporters: [
    'default',
    [
      'jest-junit',
      {
        suiteName: 'express-oauth2-jwt-bearer',
        outputDirectory: '../../test-results/express-oauth2-jwt-bearer',
      },
    ],
  ],
  moduleNameMapper: {
    '^oauth2-bearer$': '<rootDir>/../oauth2-bearer/src/',
    '^access-token-jwt$': '<rootDir>/../access-token-jwt/src/',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: {
          baseUrl: '.',
          paths: {
            'oauth2-bearer': ['../oauth2-bearer/src'],
            'access-token-jwt': ['../access-token-jwt/src'],
          },
          useUnknownInCatchVariables: false,
        },
      },
    ],
  },
};
