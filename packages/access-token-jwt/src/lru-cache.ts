/**
 *
 * This cache evicts the least recently accessed items when maxEntries is reached.
 * Each entry has a TTL (time-to-live) and is automatically evicted when expired.
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export interface LRUCacheOptions {
  /**
   * Maximum number of entries to store in the cache.
   * When this limit is reached, the least recently used entry is evicted.
   * Default: 100
   */
  maxEntries?: number;

  /**
   * Time-to-live for cache entries in milliseconds.
   * Default: 600000 (10 minutes)
   */
  ttl?: number;
}

export class LRUCache<T> {
  private cache: Map<string, CacheEntry<T>>;
  private readonly maxEntries: number;
  private readonly ttl: number;

  constructor(options: LRUCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? 100;
    this.ttl = options.ttl ?? 600000; // 10 minutes default
    this.cache = new Map();
  }

  /**
   * Get an entry from the cache.
   * Returns undefined if the entry doesn't exist or has expired.
   * Accessing an entry moves it to the end (most recently used).
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      return undefined;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    // Move to end (most recently used) by deleting and re-adding
    this.cache.delete(key);
    this.cache.set(key, entry);

    return entry.value;
  }

  /**
   * Set an entry in the cache.
   * If the cache is full, the least recently used entry is evicted first.
   */
  set(key: string, value: T): void {
    // Delete existing entry if present (will be re-added at the end)
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    // Evict least recently used entry if at capacity
    if (this.cache.size >= this.maxEntries) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    // Add new entry with expiration
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + this.ttl,
    });
  }

  /**
   * Check if a key exists in the cache and is not expired.
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Clear all entries from the cache.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get the current number of entries in the cache.
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Delete a specific entry from the cache.
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }
}
