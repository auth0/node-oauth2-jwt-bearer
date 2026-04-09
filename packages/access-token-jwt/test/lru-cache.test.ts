import { LRUCache } from '../src/lru-cache';

describe('LRUCache', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should store and retrieve values', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    cache.set('key1', 'value1');
    expect(cache.get('key1')).toBe('value1');
  });

  it('should return undefined for non-existent keys', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    expect(cache.get('nonexistent')).toBeUndefined();
  });

  it('should expire entries after TTL', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    cache.set('key1', 'value1');
    expect(cache.get('key1')).toBe('value1');

    // Advance time past TTL
    jest.advanceTimersByTime(1001);

    expect(cache.get('key1')).toBeUndefined();
  });

  it('should evict least recently used entry when maxEntries is reached', () => {
    const cache = new LRUCache<string>({ maxEntries: 3, ttl: 10000 });

    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.set('key3', 'value3');

    // All 3 entries should be present
    expect(cache.get('key1')).toBe('value1');
    expect(cache.get('key2')).toBe('value2');
    expect(cache.get('key3')).toBe('value3');

    // Adding 4th entry should evict key1 (least recently used)
    cache.set('key4', 'value4');

    expect(cache.get('key1')).toBeUndefined(); // Evicted
    expect(cache.get('key2')).toBe('value2');
    expect(cache.get('key3')).toBe('value3');
    expect(cache.get('key4')).toBe('value4');
  });

  it('should update LRU order when accessing entries', () => {
    const cache = new LRUCache<string>({ maxEntries: 3, ttl: 10000 });

    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.set('key3', 'value3');

    // Access key1 to make it most recently used
    cache.get('key1');

    // Adding key4 should evict key2 (now least recently used)
    cache.set('key4', 'value4');

    expect(cache.get('key1')).toBe('value1'); // Still present
    expect(cache.get('key2')).toBeUndefined(); // Evicted
    expect(cache.get('key3')).toBe('value3');
    expect(cache.get('key4')).toBe('value4');
  });

  it('should replace existing values', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    cache.set('key1', 'value1');
    cache.set('key1', 'value1-updated');

    expect(cache.get('key1')).toBe('value1-updated');
  });

  it('should clear all entries', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    cache.set('key1', 'value1');
    cache.set('key2', 'value2');

    expect(cache.size).toBe(2);

    cache.clear();

    expect(cache.size).toBe(0);
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBeUndefined();
  });

  it('should track cache size correctly', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    expect(cache.size).toBe(0);

    cache.set('key1', 'value1');
    expect(cache.size).toBe(1);

    cache.set('key2', 'value2');
    expect(cache.size).toBe(2);

    cache.delete('key1');
    expect(cache.size).toBe(1);
  });

  it('should use default options when not provided', () => {
    const cache = new LRUCache<string>();

    // Default maxEntries: 100, TTL: 600000 (10 minutes)
    cache.set('key1', 'value1');
    expect(cache.get('key1')).toBe('value1');

    // Should not expire after 5 minutes
    jest.advanceTimersByTime(300000);
    expect(cache.get('key1')).toBe('value1');

    // Should expire after 11 minutes
    jest.advanceTimersByTime(360000);
    expect(cache.get('key1')).toBeUndefined();
  });

  it('should handle has() method correctly', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    expect(cache.has('key1')).toBe(false);

    cache.set('key1', 'value1');
    expect(cache.has('key1')).toBe(true);

    // Advance time past TTL
    jest.advanceTimersByTime(1001);
    expect(cache.has('key1')).toBe(false);
  });

  it('should handle delete() method correctly', () => {
    const cache = new LRUCache<string>({ maxEntries: 5, ttl: 1000 });

    cache.set('key1', 'value1');
    expect(cache.has('key1')).toBe(true);

    const deleted = cache.delete('key1');
    expect(deleted).toBe(true);
    expect(cache.has('key1')).toBe(false);

    const deletedAgain = cache.delete('key1');
    expect(deletedAgain).toBe(false);
  });

  it('should work with complex objects', () => {
    interface TestData {
      id: number;
      name: string;
    }

    const cache = new LRUCache<TestData>({ maxEntries: 5, ttl: 1000 });

    const data: TestData = { id: 1, name: 'test' };
    cache.set('key1', data);

    const retrieved = cache.get('key1');
    expect(retrieved).toEqual(data);
    expect(retrieved?.id).toBe(1);
    expect(retrieved?.name).toBe('test');
  });

  it('should handle 100+ entries with default maxEntries', () => {
    const cache = new LRUCache<number>(); // Default maxEntries: 100

    // Add 150 entries
    for (let i = 0; i < 150; i++) {
      cache.set(`key${i}`, i);
    }

    // Only last 100 should be present
    expect(cache.size).toBe(100);
    expect(cache.get('key0')).toBeUndefined(); // First 50 evicted
    expect(cache.get('key49')).toBeUndefined();
    expect(cache.get('key50')).toBeDefined(); // Last 100 present
    expect(cache.get('key149')).toBe(149);
  });
});
