/**
 * Cache Manager
 * Implements cache key generation and three-tier caching architecture
 * Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
 */

import crypto from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import type { CacheKeyParams, CachedResult } from './types.js'
import type { DatabaseManager } from './database.js'

export type CacheTier = 'memory' | 'filesystem' | 'database' | 'unknown'

export interface CacheHitMetadata {
  key: string
  tier: CacheTier
  createdAt?: string
  expiresAt?: string
  fetchedAt: string
  sampleSha256?: string
}

export interface CacheHitLookup {
  data: unknown
  metadata: CacheHitMetadata
}

/**
 * LRU Cache implementation for memory caching
 */
class LRUCache<T> {
  private cache: Map<string, {
    value: T
    insertedAt: number
    createdAt: string
    expiresAt?: string
    expiresAtMs?: number
    sampleSha256?: string
  }>
  private maxSize: number
  private ttlMs: number

  constructor(maxSize: number, ttlMs: number) {
    this.cache = new Map()
    this.maxSize = maxSize
    this.ttlMs = ttlMs
  }

  getWithMeta(
    key: string
  ): { value: T; createdAt: string; expiresAt?: string; sampleSha256?: string } | null {
    const entry = this.cache.get(key)
    if (!entry) return null

    const now = Date.now()

    // Check if expired
    if (now - entry.insertedAt > this.ttlMs) {
      this.cache.delete(key)
      return null
    }

    // Check absolute source expiration (if available)
    if (entry.expiresAtMs && now > entry.expiresAtMs) {
      this.cache.delete(key)
      return null
    }

    // Move to end (most recently used)
    this.cache.delete(key)
    this.cache.set(key, entry)

    return {
      value: entry.value,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
      sampleSha256: entry.sampleSha256,
    }
  }

  get(key: string): T | null {
    const entry = this.getWithMeta(key)
    if (!entry) {
      return null
    }
    return entry.value
  }

  set(
    key: string,
    value: T,
    options?: { createdAt?: string; expiresAt?: string; sampleSha256?: string }
  ): void {
    // Remove if exists (to update position)
    this.cache.delete(key)

    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value
      if (firstKey) {
        this.cache.delete(firstKey)
      }
    }

    const createdAt = options?.createdAt || new Date().toISOString()
    const expiresAt = options?.expiresAt
    const expiresAtMs = expiresAt ? new Date(expiresAt).getTime() : undefined

    this.cache.set(key, {
      value,
      insertedAt: Date.now(),
      createdAt,
      expiresAt,
      expiresAtMs: Number.isNaN(expiresAtMs) ? undefined : expiresAtMs,
      sampleSha256: options?.sampleSha256,
    })
  }

  clear(): void {
    this.cache.clear()
  }
}

/**
 * File System Cache implementation
 */
class FileSystemCache {
  private cacheDir: string
  private ttlMs: number

  constructor(cacheDir: string, ttlMs: number) {
    this.cacheDir = cacheDir
    this.ttlMs = ttlMs
  }

  private getCachePath(key: string): string {
    // Use first 2 chars for bucketing to avoid too many files in one directory
    const bucket = key.substring(6, 8) // Skip "cache:" prefix
    return path.join(this.cacheDir, bucket, `${key}.json`)
  }

  async getWithMeta(
    key: string
  ): Promise<{ data: unknown; createdAt?: string; expiresAt?: string; sampleSha256?: string } | null> {
    try {
      const cachePath = this.getCachePath(key)
      const content = await fs.readFile(cachePath, 'utf-8')
      const cached: CachedResult = JSON.parse(content)

      // Check if expired
      if (cached.expiresAt && new Date(cached.expiresAt) < new Date()) {
        await fs.unlink(cachePath).catch(() => {}) // Ignore errors
        return null
      }

      return {
        data: cached.data,
        createdAt: cached.createdAt,
        expiresAt: cached.expiresAt,
        sampleSha256: cached.sampleSha256,
      }
    } catch (error) {
      // File doesn't exist or can't be read
      return null
    }
  }

  async get(key: string): Promise<unknown | null> {
    const cached = await this.getWithMeta(key)
    if (!cached) {
      return null
    }
    return cached.data
  }

  async set(key: string, data: unknown, ttlMs?: number, sampleSha256?: string): Promise<void> {
    try {
      const cachePath = this.getCachePath(key)
      const cacheDir = path.dirname(cachePath)

      // Ensure directory exists
      await fs.mkdir(cacheDir, { recursive: true })

      const cached: CachedResult = {
        key,
        data,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + (ttlMs || this.ttlMs)).toISOString(),
        sampleSha256,
      }

      await fs.writeFile(cachePath, JSON.stringify(cached), 'utf-8')
    } catch (error) {
      // Ignore write errors (cache is optional)
      console.warn(`Failed to write cache to filesystem: ${error}`)
    }
  }
}

/**
 * Cache Manager with three-tier architecture
 * 
 * Requirements: 20.3, 20.4, 20.5, 26.1 (cache prewarming)
 * 
 * Architecture:
 * - L1: Memory cache (LRU, 5 minutes TTL)
 * - L2: File system cache (30 days TTL)
 * - L3: Database cache
 */
export class CacheManager {
  private memoryCache: LRUCache<unknown>
  private fsCache: FileSystemCache
  private db: DatabaseManager | null
  private prewarmInProgress: boolean = false

  constructor(cacheDir: string, db?: DatabaseManager) {
    // L1: Memory cache - 1000 items, 5 minutes TTL
    this.memoryCache = new LRUCache(1000, 5 * 60 * 1000)

    // L2: File system cache - 30 days TTL
    this.fsCache = new FileSystemCache(cacheDir, 30 * 24 * 60 * 60 * 1000)

    // L3: Database cache (optional)
    this.db = db || null
  }

  /**
   * Get cached result from three-tier cache
   * 
   * Requirements: 20.3
   * 
   * Algorithm:
   * 1. Check L1 (memory cache)
   * 2. If miss, check L2 (file system cache) and populate L1
   * 3. If miss, check L3 (database cache) and populate L1 and L2
   * 4. Return null if not found in any layer
   * 
   * @param key - Cache key
   * @returns Cached data or null if not found
   */
  async getCachedResult(key: string): Promise<unknown | null> {
    const cached = await this.getCachedResultWithMetadata(key)
    return cached?.data ?? null
  }

  /**
   * Get cached result with hit metadata for observability.
   */
  async getCachedResultWithMetadata(key: string): Promise<CacheHitLookup | null> {
    // L1: Check memory cache
    const memoryResult = this.memoryCache.getWithMeta(key)
    if (memoryResult !== null) {
      return {
        data: memoryResult.value,
        metadata: {
          key,
          tier: 'memory',
          createdAt: memoryResult.createdAt,
          expiresAt: memoryResult.expiresAt,
          fetchedAt: new Date().toISOString(),
          sampleSha256: memoryResult.sampleSha256,
        },
      }
    }

    // L2: Check file system cache
    const fsResult = await this.fsCache.getWithMeta(key)
    if (fsResult !== null) {
      // Populate L1
      this.memoryCache.set(key, fsResult.data, {
        createdAt: fsResult.createdAt,
        expiresAt: fsResult.expiresAt,
        sampleSha256: fsResult.sampleSha256,
      })
      return {
        data: fsResult.data,
        metadata: {
          key,
          tier: 'filesystem',
          createdAt: fsResult.createdAt,
          expiresAt: fsResult.expiresAt,
          fetchedAt: new Date().toISOString(),
          sampleSha256: fsResult.sampleSha256,
        },
      }
    }

    // L3: Check database cache
    if (this.db) {
      const cached = await this.db.getCachedResult(key)
      if (cached) {
        // Check if expired
        if (cached.expiresAt && new Date(cached.expiresAt) < new Date()) {
          return null
        }

        let remainingTtlMs: number | undefined
        if (cached.expiresAt) {
          const remaining = new Date(cached.expiresAt).getTime() - Date.now()
          if (remaining > 0) {
            remainingTtlMs = remaining
          }
        }

        // Populate L1 and L2
        this.memoryCache.set(key, cached.data, {
          createdAt: cached.createdAt,
          expiresAt: cached.expiresAt,
          sampleSha256: cached.sampleSha256,
        })
        await this.fsCache.set(key, cached.data, remainingTtlMs, cached.sampleSha256)
        return {
          data: cached.data,
          metadata: {
            key,
            tier: 'database',
            createdAt: cached.createdAt,
            expiresAt: cached.expiresAt,
            fetchedAt: new Date().toISOString(),
            sampleSha256: cached.sampleSha256,
          },
        }
      }
    }

    return null
  }

  /**
   * Set cached result in all three tiers
   * 
   * Requirements: 20.4
   * 
   * Algorithm:
   * 1. Store in L1 (memory cache)
   * 2. Store in L2 (file system cache)
   * 3. Store in L3 (database cache) if available
   * 
   * @param key - Cache key
   * @param data - Data to cache
   * @param ttl - Time to live in milliseconds (optional)
   */
  async setCachedResult(key: string, data: unknown, ttl?: number, sampleSha256?: string): Promise<void> {
    // L1: Store in memory cache
    this.memoryCache.set(key, data, { sampleSha256 })

    // L2: Store in file system cache
    await this.fsCache.set(key, data, ttl, sampleSha256)

    // L3: Store in database cache
    if (this.db) {
      const expiresAt = ttl ? new Date(Date.now() + ttl).toISOString() : undefined
      await this.db.setCachedResult(key, data, expiresAt, sampleSha256)
    }
  }

  /**
   * Clear all caches
   */
  clearAll(): void {
    this.memoryCache.clear()
  }

  /**
   * Prewarm cache by loading frequently accessed data into memory
   * 
   * Requirements: 26.1 (cache prewarming)
   * 
   * Strategy:
   * 1. Load recent cache entries from database
   * 2. Populate L1 (memory) and L2 (filesystem) caches
   * 3. Prioritize entries with high access frequency
   * 
   * @param maxEntries - Maximum number of entries to prewarm (default: 100)
   */
  async prewarmCache(maxEntries: number = 100): Promise<number> {
    if (this.prewarmInProgress) {
      return 0 // Already prewarming
    }

    this.prewarmInProgress = true
    let prewarmedCount = 0

    try {
      if (!this.db) {
        return 0 // No database to prewarm from
      }

      // Get recent cache entries from database
      const recentEntries = await this.db.getRecentCacheEntries(maxEntries)

      // Load into memory and filesystem caches
      for (const entry of recentEntries) {
        try {
          // Skip expired entries
          if (entry.expires_at && new Date(entry.expires_at) < new Date()) {
            continue
          }

          // Parse data
          const data = JSON.parse(entry.data)

          // Populate L1 (memory cache)
          this.memoryCache.set(entry.key, data)

          // Populate L2 (filesystem cache) - async, don't wait
          this.fsCache.set(entry.key, data).catch(() => {
            // Ignore filesystem errors during prewarming
          })

          prewarmedCount++
        } catch (error) {
          // Skip invalid entries
          continue
        }
      }

      return prewarmedCount
    } finally {
      this.prewarmInProgress = false
    }
  }

  /**
   * Prewarm cache for a specific sample
   * Loads all cached results for a sample into memory
   * 
   * Requirements: 26.1 (cache prewarming)
   * 
   * @param sampleSha256 - SHA256 hash of the sample
   * @returns Number of entries prewarmed
   */
  async prewarmSampleCache(sampleSha256: string): Promise<number> {
    if (!this.db) {
      return 0
    }

    let prewarmedCount = 0

    // Get all cache entries for this sample
    const sampleEntries = await this.db.getCacheEntriesBySample(sampleSha256)

    for (const entry of sampleEntries) {
      try {
        // Skip expired entries
        if (entry.expires_at && new Date(entry.expires_at) < new Date()) {
          continue
        }

        // Parse data
        const data = JSON.parse(entry.data)

        // Populate L1 (memory cache)
        this.memoryCache.set(entry.key, data)

        prewarmedCount++
      } catch (error) {
        // Skip invalid entries
        continue
      }
    }

    return prewarmedCount
  }
}

/**
 * Generate deterministic cache key from parameters
 * 
 * Requirements: 20.1, 20.2
 * 
 * Algorithm:
 * 1. Normalize arguments (sort keys, remove defaults)
 * 2. Create canonical representation
 * 3. Generate SHA256 hash
 * 
 * @param params - Cache key parameters
 * @returns Cache key string in format "cache:<sha256>"
 */
export function generateCacheKey(params: CacheKeyParams): string {
  // Create normalized object with sorted keys
  const normalized = {
    sampleSha256: params.sampleSha256,
    toolName: params.toolName,
    toolVersion: params.toolVersion,
    args: normalizeArgs(params.args),
    ...(params.rulesetVersion && { rulesetVersion: params.rulesetVersion })
  }

  // Sort keys at top level to ensure deterministic order
  const sortedKeys = Object.keys(normalized).sort()
  const sortedNormalized = sortedKeys.reduce((acc, key) => {
    acc[key] = normalized[key as keyof typeof normalized]
    return acc
  }, {} as Record<string, unknown>)

  // Generate canonical JSON string
  const keyString = JSON.stringify(sortedNormalized)

  // Generate SHA256 hash
  const hash = crypto.createHash('sha256').update(keyString).digest('hex')

  return `cache:${hash}`
}

/**
 * Normalize arguments for cache key generation
 * 
 * Requirements: 20.2
 * 
 * Normalization rules:
 * 1. Sort object keys recursively
 * 2. Remove null and undefined values
 * 3. Recursively normalize nested objects
 * 4. Preserve arrays as-is (order matters)
 * 
 * @param args - Arguments object to normalize
 * @returns Normalized arguments object
 */
export function normalizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  // Handle null/undefined
  if (args === null || args === undefined) {
    return {}
  }

  // Sort keys and filter out null/undefined values
  const sortedKeys = Object.keys(args).sort()

  const normalized = sortedKeys.reduce((acc, key) => {
    const value = args[key]

    // Skip null and undefined values
    if (value === null || value === undefined) {
      return acc
    }

    // Recursively normalize nested objects
    if (typeof value === 'object' && !Array.isArray(value)) {
      acc[key] = normalizeArgs(value as Record<string, unknown>)
    } else {
      // Keep primitives and arrays as-is
      acc[key] = value
    }

    return acc
  }, {} as Record<string, unknown>)

  return normalized
}

/**
 * Parameters to filter from cache key generation (unstable params)
 * These parameters don't affect the result and should be ignored
 * Tasks: mcp-server-optimization 1.1
 */
const UNSTABLE_PARAMS = new Set([
  'timestamp',
  'random',
  'nonce',
  'request_id',
  'session_id',
  'force_refresh',
  'persist_artifact',
  'register_analysis',
  'session_tag',
  'timeout',
  'timeout_ms',
  'timeout_sec',
  'max_tokens',
  'temperature',
  'include_raw',
  'verbose',
  'debug',
])

/**
 * Filter unstable parameters that don't affect the cache result
 * Tasks: mcp-server-optimization 1.1
 */
export function filterUnstableParams(args: Record<string, unknown>): Record<string, unknown> {
  if (!args || typeof args !== 'object') {
    return args || {}
  }

  const filtered: Record<string, unknown> = {}
  
  for (const [key, value] of Object.entries(args)) {
    if (!UNSTABLE_PARAMS.has(key)) {
      filtered[key] = value
    }
  }
  
  return filtered
}

/**
 * Generate cache key with intelligent parameter filtering
 * Tasks: mcp-server-optimization 1.1, 1.2
 */
export function generateSmartCacheKey(params: CacheKeyParams): string {
  // Filter unstable parameters from args
  const filteredArgs = filterUnstableParams(params.args)
  
  // Create normalized object with sorted keys
  const normalized = {
    sampleSha256: params.sampleSha256,
    toolName: params.toolName,
    toolVersion: params.toolVersion,
    args: normalizeArgs(filteredArgs),
    ...(params.rulesetVersion && { rulesetVersion: params.rulesetVersion })
  }

  // Sort keys at top level to ensure deterministic order
  const sortedKeys = Object.keys(normalized).sort()
  const sortedNormalized = sortedKeys.reduce((acc, key) => {
    acc[key] = normalized[key as keyof typeof normalized]
    return acc
  }, {} as Record<string, unknown>)

  // Generate canonical JSON string
  const keyString = JSON.stringify(sortedNormalized)

  // Generate SHA256 hash
  const hash = crypto.createHash('sha256').update(keyString).digest('hex')

  return `cache:${hash}`
}


