/**
 * Smart Cache tests
 * Tasks: mcp-server-optimization 1.5, 1.6
 */

import { describe, test, expect } from '@jest/globals'
import { generateSmartCacheKey, filterUnstableParams } from '../../src/cache-manager.js'
import type { CacheKeyParams } from '../../src/types.js'

describe('mcp-server-optimization - Smart Cache', () => {
  describe('filterUnstableParams', () => {
    test('should filter timestamp parameter', () => {
      const args = {
        sample_id: 'sha256:abc123',
        timestamp: Date.now(),
        min_len: 4,
      }

      const filtered = filterUnstableParams(args)

      expect(filtered.timestamp).toBeUndefined()
      expect(filtered.sample_id).toBe('sha256:abc123')
      expect(filtered.min_len).toBe(4)
    })

    test('should filter session_tag parameter', () => {
      const args = {
        sample_id: 'sha256:abc123',
        session_tag: 'session-123',
        mode: 'preview',
      }

      const filtered = filterUnstableParams(args)

      expect(filtered.session_tag).toBeUndefined()
      expect(filtered.mode).toBe('preview')
    })

    test('should filter multiple unstable params', () => {
      const args = {
        sample_id: 'sha256:abc123',
        force_refresh: true,
        timeout_ms: 30000,
        persist_artifact: true,
        min_len: 4,
      }

      const filtered = filterUnstableParams(args)

      expect(filtered.force_refresh).toBeUndefined()
      expect(filtered.timeout_ms).toBeUndefined()
      expect(filtered.persist_artifact).toBeUndefined()
      expect(filtered.min_len).toBe(4)
    })

    test('should keep stable params', () => {
      const args = {
        sample_id: 'sha256:abc123',
        min_len: 4,
        encoding: 'all',
        max_strings: 500,
      }

      const filtered = filterUnstableParams(args)

      expect(filtered).toEqual(args)
    })

    test('should handle empty args', () => {
      expect(filterUnstableParams({})).toEqual({})
      expect(filterUnstableParams(null as any)).toEqual({})
      expect(filterUnstableParams(undefined as any)).toEqual({})
    })
  })

  describe('generateSmartCacheKey', () => {
    test('should generate same key for same params', () => {
      const params1: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4, encoding: 'all' },
      }

      const params2: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4, encoding: 'all' },
      }

      const key1 = generateSmartCacheKey(params1)
      const key2 = generateSmartCacheKey(params2)

      expect(key1).toBe(key2)
    })

    test('should generate different keys for different samples', () => {
      const params1: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4 },
      }

      const params2: CacheKeyParams = {
        sampleSha256: 'def456',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4 },
      }

      const key1 = generateSmartCacheKey(params1)
      const key2 = generateSmartCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should ignore unstable params in key generation', () => {
      const params1: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4, timestamp: Date.now() },
      }

      const params2: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { min_len: 4, timestamp: Date.now() + 1000 },
      }

      const key1 = generateSmartCacheKey(params1)
      const key2 = generateSmartCacheKey(params2)

      // Keys should be same despite different timestamps
      expect(key1).toBe(key2)
    })

    test('should normalize object keys', () => {
      const params1: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { z: 1, a: 2, m: 3 },
      }

      const params2: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { a: 2, m: 3, z: 1 },
      }

      const key1 = generateSmartCacheKey(params1)
      const key2 = generateSmartCacheKey(params2)

      expect(key1).toBe(key2)
    })

    test('should generate valid cache key format', () => {
      const params: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {},
      }

      const key = generateSmartCacheKey(params)

      expect(key).toMatch(/^cache:[a-f0-9]{64}$/)
    })
  })

  describe('cache key stability', () => {
    test('should produce consistent keys across multiple calls', () => {
      const params: CacheKeyParams = {
        sampleSha256: 'test123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {
          min_len: 4,
          encoding: 'all',
          max_strings: 500,
          force_refresh: false,
          session_tag: 'test-session',
        },
      }

      const keys = Array(10).fill(null).map(() => generateSmartCacheKey(params))

      // All keys should be identical
      expect(new Set(keys).size).toBe(1)
    })

    test('should handle nested objects', () => {
      const params1: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {
          nested: { z: 1, a: 2 },
          timeout: 30000,
        },
      }

      const params2: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {
          nested: { a: 2, z: 1 },
          timeout: 30000,
        },
      }

      const key1 = generateSmartCacheKey(params1)
      const key2 = generateSmartCacheKey(params2)

      // Should be same despite nested key order and timeout param
      expect(key1).toBe(key2)
    })
  })

  describe('performance characteristics', () => {
    test('should generate keys quickly', () => {
      const params: CacheKeyParams = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: { min_len: 4 },
      }

      const start = Date.now()
      for (let i = 0; i < 1000; i++) {
        generateSmartCacheKey(params)
      }
      const elapsed = Date.now() - start

      // Should generate 1000 keys in < 100ms
      expect(elapsed).toBeLessThan(100)
    })
  })
})
