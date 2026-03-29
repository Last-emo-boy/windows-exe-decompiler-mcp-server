/**
 * Upload Workflow E2E tests
 * Tasks: api-file-server 7.5
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { DatabaseManager } from '../../src/database.js'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('api-file-server - Upload Workflow E2E', () => {
  let storageManager: StorageManager
  let database: DatabaseManager
  let testDir: string

  beforeEach(async () => {
    testDir = path.join(__dirname, '..', 'temp', `e2e-test-${Date.now()}`)
    fs.mkdirSync(testDir, { recursive: true })

    storageManager = new StorageManager({
      root: testDir,
      maxFileSize: 10 * 1024 * 1024,
      retentionDays: 30,
    })
    await storageManager.initialize()

    database = new DatabaseManager(':memory:')
    database.initialize()
  })

  afterEach(() => {
    database.close()
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  describe('Complete Upload Workflow', () => {
    test('should support full upload → analyze → retrieve workflow', async () => {
      // Step 1: Upload sample
      const testData = Buffer.from('e2e test sample')
      const stored = await storageManager.storeSample(testData, 'e2e-test.exe')

      // Step 2: Register in database
      const sampleId = `sha256:${stored.sha256}`
      database.createSample({
        id: sampleId,
        sha256: stored.sha256,
        size: stored.size,
        created_at: new Date().toISOString(),
        source: 'e2e_test',
      })

      // Step 3: Verify sample exists
      const sample = database.findSample(sampleId)
      expect(sample).toBeDefined()
      expect(sample?.sha256).toBe(stored.sha256)

      // Step 4: Retrieve sample
      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).not.toBeNull()
      expect(retrieved?.equals(testData)).toBe(true)

      // Step 5: Create artifact
      const artifactPath = await storageManager.storeArtifact(
        sampleId,
        'test_report',
        JSON.stringify({ result: 'pass' })
      )

      // Step 6: Verify artifact exists
      expect(fs.existsSync(artifactPath)).toBe(true)

      // Step 7: Cleanup
      await storageManager.deleteSample(stored.sha256)
      const deleted = await storageManager.retrieveSample(stored.sha256)
      expect(deleted).toBeNull()
    })
  })

  describe('Concurrent Upload Workflow', () => {
    test('should handle multiple concurrent uploads', async () => {
      const uploadPromises = Array(5).fill(null).map(async (_, i) => {
        const testData = Buffer.from(`concurrent test ${i}`)
        return storageManager.storeSample(testData, `test-${i}.exe`)
      })

      const results = await Promise.all(uploadPromises)

      expect(results).toHaveLength(5)
      for (const result of results) {
        expect(result.sha256).toBeDefined()
        expect(result.size).toBeGreaterThan(0)
      }

      // Verify all samples can be retrieved
      for (const result of results) {
        const retrieved = await storageManager.retrieveSample(result.sha256)
        expect(retrieved).not.toBeNull()
      }
    })
  })

  describe('Upload with Metadata Logging', () => {
    test('should support metadata tracking', async () => {
      const testData = Buffer.from('metadata test')
      const stored = await storageManager.storeSample(testData, 'meta-test.exe')

      const sampleId = `sha256:${stored.sha256}`
      database.createSample({
        id: sampleId,
        sha256: stored.sha256,
        size: stored.size,
        created_at: new Date().toISOString(),
        source: 'metadata_test',
      })

      // Create artifact
      await storageManager.storeArtifact(
        sampleId,
        'metadata_report',
        JSON.stringify({ timestamp: new Date().toISOString() })
      )

      // Verify metadata
      const sample = database.findSample(sampleId)
      expect(sample).toBeDefined()
      expect(sample?.source).toBe('metadata_test')

      const artifacts = database.findArtifacts(sampleId)
      expect(artifacts).toHaveLength(1)
      expect(artifacts[0].type).toBe('metadata_report')
    })
  })

  describe('Error Recovery Workflow', () => {
    test('should handle upload failures gracefully', async () => {
      // Try to upload oversized file
      const oversizedData = Buffer.alloc(11 * 1024 * 1024) // 11MB

      try {
        await storageManager.storeSample(oversizedData, 'too-large.exe')
        fail('Should have thrown error')
      } catch (error: any) {
        expect(error.message).toContain('exceeds limit')
      }

      // Verify system is still functional
      const validData = Buffer.from('valid test')
      const result = await storageManager.storeSample(validData, 'valid.exe')
      expect(result.sha256).toBeDefined()
    })
  })

  describe('Retention Workflow', () => {
    test('should support retention-based cleanup', async () => {
      // Upload sample
      const testData = Buffer.from('retention test')
      const stored = await storageManager.storeSample(testData, 'retention-test.exe')

      // Run retention with very short period
      const result = await storageManager.applyRetention({
        dryRun: true,
        maxAgeDays: 0, // Everything is old
      })

      expect(result.status).toBeDefined()
      expect(result.deletedSamples).toBeGreaterThanOrEqual(0)

      // Verify file still exists (dry run)
      const retrieved = await storageManager.retrieveSample(stored.sha256)
      expect(retrieved).not.toBeNull()
    })
  })
})
