import getToken from '../src/get-token';

describe('get-token', () => {
  test('should return token', () => {
    expect(getToken()).toEqual('token');
  });
});
