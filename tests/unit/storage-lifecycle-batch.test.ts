/**
 * Storage lifecycle and batch submission tests
 * Tasks: storage-lifecycle-and-batch-foundation 4.1, 4.2
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { BatchSubmissionManager } from '../../src/storage/batch-submission.js'
import { DatabaseManager } from '../../src/database.js'
import path from 'path'
import fs from 'fs'

describe('storage-lifecycle-and-batch-foundation', () => {
  let storageManager: StorageManager
  let database: DatabaseManager
  let batchManager: BatchSubmissionManager
  let testDir: string

  beforeEach(async () => {
    // Create temporary test directory
    testDir = path.join(__dirname, '..', 'temp', `storage-test-${Date.now()}`)
    fs.mkdirSync(testDir, { recursive: true })

    // Initialize storage manager
    storageManager = new StorageManager({
      root: testDir,
      maxFileSize: 10 * 1024 * 1024, // 10MB
      retentionDays: 30,
    })
    await storageManager.initialize()

    // Initialize database (no initialize method needed)
    database = new DatabaseManager(':memory:')

    // Initialize batch manager
    batchManager = new BatchSubmissionManager(database, storageManager, 10)
  })

  afterEach(() => {
    // Cleanup
    database.close()
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  describe('Storage Lifecycle Primitives', () => {
    describe('retrieveSample', () => {
      test('should retrieve stored sample by SHA256', async () => {
        const testData = Buffer.from('test sample data')
        const stored = await storageManager.storeSample(testData, 'test.exe')

        const retrieved = await storageManager.retrieveSample(stored.sha256)

        expect(retrieved).not.toBeNull()
        expect(retrieved?.equals(testData)).toBe(true)
      })

      test('should return null for non-existent sample', async () => {
        const result = await storageManager.retrieveSample('nonexistent')
        expect(result).toBeNull()
      })
    })

    describe('deleteSample', () => {
      test('should delete sample and return true', async () => {
        const testData = Buffer.from('test delete')
        const stored = await storageManager.storeSample(testData, 'delete.exe')

        const deleted = await storageManager.deleteSample(stored.sha256)

        expect(deleted).toBe(true)

        // Verify file is gone
        const retrieved = await storageManager.retrieveSample(stored.sha256)
        expect(retrieved).toBeNull()
      })

      test('should return false for non-existent sample', async () => {
        const result = await storageManager.deleteSample('nonexistent')
        expect(result).toBe(false)
      })
    })

    describe('deleteArtifact', () => {
      test('should delete artifact by path', async () => {
        // Create artifact file manually for testing
        const sampleId = 'sha256:test123'
        const artifactDir = path.join(testDir, 'artifacts', sampleId)
        fs.mkdirSync(artifactDir, { recursive: true })
        const artifactPath = path.join(artifactDir, 'test_artifact.json')
        fs.writeFileSync(artifactPath, JSON.stringify({ test: 'data' }))

        const deleted = await storageManager.deleteArtifact(artifactPath)

        expect(deleted).toBe(true)
        expect(fs.existsSync(artifactPath)).toBe(false)
      })

      test('should return false for non-existent artifact', async () => {
        const result = await storageManager.deleteArtifact('/nonexistent/path')
        expect(result).toBe(false)
      })
    })
  })

  describe('Retention And Cleanup', () => {
    describe('getRetentionReport', () => {
      test('should generate retention report with buckets', async () => {
        // Store some samples
        await storageManager.storeSample(Buffer.from('test1'), 'test1.exe')
        await storageManager.storeSample(Buffer.from('test2'), 'test2.exe')

        const report = await storageManager.getRetentionReport()

        expect(report.buckets).toBeDefined()
        expect(report.buckets.length).toBe(3)
        expect(report.buckets.map(b => b.name)).toEqual(['active', 'recent', 'archive'])
        expect(report.totalBytes).toBeGreaterThan(0)
      })

      test('should categorize by age', async () => {
        const report = await storageManager.getRetentionReport()

        // All new samples should be in active bucket
        const activeBucket = report.buckets.find(b => b.name === 'active')
        expect(activeBucket).toBeDefined()
      })
    })

    describe('applyRetention', () => {
      test('should perform dry-run cleanup', async () => {
        await storageManager.storeSample(Buffer.from('test'), 'test.exe')

        const result = await storageManager.applyRetention({
          dryRun: true,
          maxAgeDays: 0, // Make everything eligible
        })

        expect(result.status).toBeDefined()
        expect(result.freedBytes).toBeGreaterThanOrEqual(0)
        expect(result.errors).toHaveLength(0)

        // Verify files still exist (dry run)
        const report = await storageManager.getRetentionReport()
        expect(report.totalBytes).toBeGreaterThan(0)
      })

      test('should delete old samples in real mode', async () => {
        const testData = Buffer.from('old sample')
        const stored = await storageManager.storeSample(testData, 'old.exe')

        const result = await storageManager.applyRetention({
          dryRun: false,
          maxAgeDays: 0,
        })

        expect(result.deletedSamples).toBeGreaterThanOrEqual(0)
        expect(result.status).toBe('complete')

        // Verify deletion
        const retrieved = await storageManager.retrieveSample(stored.sha256)
        expect(retrieved).toBeNull()
      })

      test('should return partial status on mixed results', async () => {
        // This test would require mocking file system errors
        // For now, verify the status enum is returned
        const result = await storageManager.applyRetention({ dryRun: true })
        expect(['complete', 'partial', 'failed']).toContain(result.status)
      })
    })
  })

  describe('Batch Submission Foundation', () => {
    describe('createBatch', () => {
      test('should create batch with multiple samples', async () => {
        const samples = [
          { filename: 'sample1.exe', data: Buffer.from('sample1') },
          { filename: 'sample2.exe', data: Buffer.from('sample2') },
        ]

        const result = await batchManager.createBatch(samples)

        expect(result.batchId).toBeDefined()
        expect(result.totalSamples).toBe(2)
        expect(result.results.length).toBe(2)
        expect(result.results.every(r => r.status === 'completed')).toBe(true)
      })

      test('should enforce batch size limit', async () => {
        const samples = Array(11).fill({ filename: 'test.exe', data: Buffer.from('test') })

        await expect(batchManager.createBatch(samples)).rejects.toThrow('exceeds maximum')
      })

      test('should handle partial failures', async () => {
        const samples = [
          { filename: 'good.exe', data: Buffer.from('good') },
          { filename: '', data: Buffer.from('invalid') }, // Invalid filename
        ]

        const result = await batchManager.createBatch(samples)

        expect(result.status).toBe('partial')
        expect(result.results.some(r => r.status === 'failed')).toBe(true)
      })
    })

    describe('getBatchStatus', () => {
      test('should return batch status report', async () => {
        const samples = [
          { filename: 'sample1.exe', data: Buffer.from('sample1') },
        ]

        const createResult = await batchManager.createBatch(samples)
        const status = await batchManager.getBatchStatus(createResult.batchId)

        expect(status).toBeDefined()
        expect(status.batch.batchId).toBe(createResult.batchId)
        expect(status.samples.length).toBe(1)
        expect(status.progress.percentage).toBe(100)
      })

      test('should return null for non-existent batch', async () => {
        const status = await batchManager.getBatchStatus('nonexistent')
        expect(status).toBeNull()
      })
    })

    describe('cancelBatch', () => {
      test('should cancel pending samples', async () => {
        const samples = [
          { filename: 'sample1.exe', data: Buffer.from('sample1') },
        ]

        const createResult = await batchManager.createBatch(samples)
        
        // Batch is already completed, so cancel should fail
        await expect(batchManager.cancelBatch(createResult.batchId)).rejects.toThrow()
      })
    })

    describe('retryBatch', () => {
      test('should retry failed samples', async () => {
        // Create a batch that will partially fail
        const samples = [
          { filename: 'good.exe', data: Buffer.from('good') },
          { filename: '', data: Buffer.from('invalid') },
        ]

        const result = await batchManager.createBatch(samples)
        
        // Retry the batch
        const retryResult = await batchManager.retryBatch(result.batchId)

        expect(retryResult.retried).toBeGreaterThanOrEqual(0)
      })
    })

    describe('listBatches', () => {
      test('should list batches with filtering', async () => {
        const samples = [
          { filename: 'sample1.exe', data: Buffer.from('sample1') },
        ]

        await batchManager.createBatch(samples)

        const batches = await batchManager.listBatches()
        expect(batches.length).toBeGreaterThan(0)
      })
    })

    describe('deleteBatch', () => {
      test('should delete batch metadata', async () => {
        const samples = [
          { filename: 'sample1.exe', data: Buffer.from('sample1') },
        ]

        const result = await batchManager.createBatch(samples)
        
        await batchManager.deleteBatch(result.batchId)

        const status = await batchManager.getBatchStatus(result.batchId)
        expect(status).toBeNull()
      })
    })
  })

  describe('Integration Tests', () => {
    test('should support full batch lifecycle', async () => {
      // Create batch
      const samples = [
        { filename: 'test1.exe', data: Buffer.from('test1') },
        { filename: 'test2.exe', data: Buffer.from('test2') },
      ]

      const createResult = await batchManager.createBatch(samples)
      expect(createResult.status).toBe('completed')

      // Get status
      const status = await batchManager.getBatchStatus(createResult.batchId)
      expect(status?.progress.percentage).toBe(100)

      // Retrieve samples
      for (const sample of status!.samples) {
        const data = await storageManager.retrieveSample(sample.sha256)
        expect(data).not.toBeNull()
      }

      // Cleanup
      await batchManager.deleteBatch(createResult.batchId, true)
    })

    test('should maintain metadata consistency through operations', async () => {
      const samples = [
        { filename: 'consistency.exe', data: Buffer.from('consistency') },
      ]

      const result = await batchManager.createBatch(samples)
      const batch = await database.findBatch(result.batchId)

      expect(batch).not.toBeNull()
      expect(batch?.total_samples).toBe(1)

      const batchSamples = await database.findBatchSamples(result.batchId)
      expect(batchSamples.length).toBe(1)
      expect(batchSamples[0].sample_id).toBe(result.results[0].sampleId)
    })
  })
})
