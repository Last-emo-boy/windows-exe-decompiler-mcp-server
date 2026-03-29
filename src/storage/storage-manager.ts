/**
 * Storage Manager
 * Manages file storage for samples and artifacts
 */

import fs from 'fs/promises'
import path from 'path'
import crypto from 'crypto'
import { logger } from '../logger.js'

export interface StorageConfig {
  root: string
  maxFileSize: number  // bytes
  retentionDays: number
}

export interface StoredFile {
  path: string
  filename: string
  size: number
  sha256: string
  createdAt: string
}

export interface StagedUpload {
  path: string
  filename: string
  size: number
  createdAt: string
}

export class StorageManager {
  private config: StorageConfig

  constructor(config: StorageConfig) {
    this.config = config
  }

  /**
   * Initialize storage directories
   */
  async initialize(): Promise<void> {
    const dirs = [
      this.config.root,
      path.join(this.config.root, 'samples'),
      path.join(this.config.root, 'artifacts'),
      path.join(this.config.root, 'uploads'),
      path.join(this.config.root, '.metadata'),
    ]

    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true })
    }

    logger.info(`Storage initialized at ${this.config.root}`)
  }

  /**
   * Store sample file
   */
  async storeSample(
    data: Buffer,
    filename: string,
    _source?: string
  ): Promise<StoredFile> {
    // Check file size
    if (data.length > this.config.maxFileSize) {
      throw new Error(
        `File size ${data.length} exceeds limit ${this.config.maxFileSize}`
      )
    }

    // Compute hash
    const sha256 = crypto.createHash('sha256').update(data).digest('hex')

    // Create storage path with date partitioning
    const date = new Date().toISOString().split('T')[0]
    const storageDir = path.join(this.config.root, 'samples', date)
    await fs.mkdir(storageDir, { recursive: true })

    // Store file
    const safeFilename = this.sanitizeFilename(filename)
    const storagePath = path.join(storageDir, `${sha256}_${safeFilename}`)
    await fs.writeFile(storagePath, data)

    logger.info(`Stored sample: ${storagePath}`)

    return {
      path: storagePath,
      filename: safeFilename,
      size: data.length,
      sha256,
      createdAt: new Date().toISOString(),
    }
  }

  /**
   * Stage an uploaded file under the shared uploads root.
   */
  async stageUpload(
    sessionToken: string,
    data: Buffer,
    filename: string
  ): Promise<StagedUpload> {
    if (data.length > this.config.maxFileSize) {
      throw new Error(
        `File size ${data.length} exceeds limit ${this.config.maxFileSize}`
      )
    }

    const createdAt = new Date().toISOString()
    const safeFilename = this.sanitizeFilename(filename)
    const date = createdAt.split('T')[0]
    const uploadDir = path.join(this.config.root, 'uploads', date)
    await fs.mkdir(uploadDir, { recursive: true })

    const stagedPath = path.join(uploadDir, `${sessionToken}_${safeFilename}`)
    await fs.writeFile(stagedPath, data)

    logger.info(`Staged upload: ${stagedPath}`)

    return {
      path: stagedPath,
      filename: safeFilename,
      size: data.length,
      createdAt,
    }
  }

  /**
   * Read bytes from a staged upload.
   */
  async readStagedUpload(stagedPath: string): Promise<Buffer> {
    return fs.readFile(stagedPath)
  }

  /**
   * Delete a staged upload if it exists.
   */
  async deleteStagedUpload(stagedPath: string): Promise<void> {
    await fs.unlink(stagedPath).catch(() => {})
  }

  /**
   * Best-effort check for staged upload presence.
   */
  async hasStagedUpload(stagedPath: string): Promise<boolean> {
    try {
      await fs.access(stagedPath)
      return true
    } catch {
      return false
    }
  }

  /**
   * Retrieve sample file by SHA256
   */
  async retrieveSample(sha256: string): Promise<Buffer | null> {
    try {
      // Search through date-partitioned directories
      const samplesDir = path.join(this.config.root, 'samples')
      const dateDirs = await fs.readdir(samplesDir, { withFileTypes: true })
      
      for (const dateDir of dateDirs.filter(d => d.isDirectory())) {
        const datePath = path.join(samplesDir, dateDir.name)
        const files = await fs.readdir(datePath)
        
        for (const file of files) {
          if (file.startsWith(sha256)) {
            const filePath = path.join(datePath, file)
            return await fs.readFile(filePath)
          }
        }
      }
      
      logger.warn(`Sample not found: ${sha256}`)
      return null
    } catch (error) {
      logger.error('Error retrieving sample: ' + JSON.stringify(error))
      throw error
    }
  }

  /**
   * Retrieve artifact by ID
   */
  async retrieveArtifact(artifactId: string): Promise<Buffer | null> {
    try {
      // Artifacts are stored under artifacts/<sampleId>/<artifactType>.json
      // Search for the artifact by ID
      const artifactsDir = this.config.root
      const sampleDirs = await fs.readdir(path.join(artifactsDir, 'artifacts'), { withFileTypes: true })
      
      for (const sampleDir of sampleDirs.filter(d => d.isDirectory())) {
        const samplePath = path.join(artifactsDir, 'artifacts', sampleDir.name)
        const files = await fs.readdir(samplePath, { withFileTypes: true })
        
        for (const file of files.filter(f => f.isFile())) {
          const filePath = path.join(samplePath, file.name)
          // Check if this file matches the artifact ID pattern
          if (file.name.includes(artifactId) || file.name === `${artifactId}.json`) {
            return await fs.readFile(filePath)
          }
        }
      }
      
      logger.warn(`Artifact not found: ${artifactId}`)
      return null
    } catch (error) {
      logger.error('Error retrieving artifact: ' + JSON.stringify(error))
      throw error
    }
  }

  /**
   * Delete sample file by SHA256
   * Returns true if deleted, false if not found
   */
  async deleteSample(sha256: string): Promise<boolean> {
    try {
      const samplesDir = path.join(this.config.root, 'samples')
      const dateDirs = await fs.readdir(samplesDir, { withFileTypes: true })
      
      for (const dateDir of dateDirs.filter(d => d.isDirectory())) {
        const datePath = path.join(samplesDir, dateDir.name)
        const files = await fs.readdir(datePath)
        
        for (const file of files) {
          if (file.startsWith(sha256)) {
            const filePath = path.join(datePath, file)
            await fs.unlink(filePath)
            logger.info(`Deleted sample: ${filePath}`)
            return true
          }
        }
      }
      
      logger.warn(`Sample not found for deletion: ${sha256}`)
      return false
    } catch (error) {
      logger.error('Error deleting sample: ' + JSON.stringify(error))
      throw error
    }
  }

  /**
   * Delete artifact by path
   * Returns true if deleted, false if not found
   */
  async deleteArtifact(artifactPath: string): Promise<boolean> {
    try {
      const fullPath = path.isAbsolute(artifactPath)
        ? artifactPath
        : path.join(this.config.root, artifactPath)
      
      await fs.unlink(fullPath)
      logger.info(`Deleted artifact: ${fullPath}`)
      return true
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        logger.warn(`Artifact not found for deletion: ${artifactPath}`)
        return false
      }
      logger.error('Error deleting artifact: ' + JSON.stringify(error))
      throw error
    }
  }

  /**
   * Get storage statistics
   */
  async getStats(): Promise<{
    usedBytes: number
    sampleCount: number
    artifactCount: number
  }> {
    const usedBytes = await this.calculateDirectorySize(this.config.root)
    const sampleCount = await this.countFiles(path.join(this.config.root, 'samples'))
    const artifactCount = await this.countFiles(path.join(this.config.root, 'artifacts'))

    return {
      usedBytes,
      sampleCount,
      artifactCount,
    }
  }

  /**
   * Calculate directory size
   */
  private async calculateDirectorySize(dir: string): Promise<number> {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true })
      let totalSize = 0

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name)
        if (entry.isDirectory()) {
          totalSize += await this.calculateDirectorySize(fullPath)
        } else {
          const stats = await fs.stat(fullPath)
          totalSize += stats.size
        }
      }

      return totalSize
    } catch (error) {
      logger.error('Error calculating directory size: ' + JSON.stringify(error))
      return 0
    }
  }

  /**
   * Count files in directory
   */
  private async countFiles(dir: string): Promise<number> {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true })
      let count = 0

      for (const entry of entries) {
        if (entry.isDirectory()) {
          count += await this.countFiles(path.join(dir, entry.name))
        } else {
          count++
        }
      }

      return count
    } catch (error) {
      logger.error('Error counting files: ' + JSON.stringify(error))
      return 0
    }
  }

  private sanitizeFilename(filename: string): string {
    const basename = path.basename(filename.replace(/\\/g, '/')).trim()
    const safe = basename.replace(/[^a-zA-Z0-9._-]/g, '_')
    return safe.length > 0 ? safe : 'sample.bin'
  }

  /**
   * Get retention report showing storage usage by retention bucket
   */
  async getRetentionReport(): Promise<{
    buckets: Array<{
      name: 'active' | 'recent' | 'archive'
      sampleCount: number
      artifactCount: number
      totalBytes: number
      oldestDate: string
      newestDate: string
    }>
    totalBytes: number
    cleanupEstimate: number
  }> {
    const now = new Date()
    const activeDays = 7
    const recentDays = 30
    
    const buckets = {
      active: { sampleCount: 0, artifactCount: 0, totalBytes: 0, dates: [] as string[] },
      recent: { sampleCount: 0, artifactCount: 0, totalBytes: 0, dates: [] as string[] },
      archive: { sampleCount: 0, artifactCount: 0, totalBytes: 0, dates: [] as string[] },
    }

    // Analyze samples
    const samplesDir = path.join(this.config.root, 'samples')
    const dateDirs = await fs.readdir(samplesDir, { withFileTypes: true }).catch(() => [])
    
    for (const dateDir of dateDirs.filter(d => d.isDirectory())) {
      const datePath = path.join(samplesDir, dateDir.name)
      const dateStr = dateDir.name
      const date = new Date(dateStr)
      const daysOld = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24))
      
      const files = await fs.readdir(datePath)
      let bucketSize = 0
      
      for (const file of files) {
        const filePath = path.join(datePath, file)
        const stats = await fs.stat(filePath).catch(() => null)
        if (stats) {
          bucketSize += stats.size
        }
      }

      let bucket: keyof typeof buckets
      if (daysOld <= activeDays) {
        bucket = 'active'
      } else if (daysOld <= recentDays) {
        bucket = 'recent'
      } else {
        bucket = 'archive'
      }

      buckets[bucket].sampleCount += files.length
      buckets[bucket].totalBytes += bucketSize
      buckets[bucket].dates.push(dateStr)
    }

    // Analyze artifacts
    const artifactsDir = path.join(this.config.root, 'artifacts')
    const sampleDirs = await fs.readdir(artifactsDir, { withFileTypes: true }).catch(() => [])
    
    for (const sampleDir of sampleDirs.filter(d => d.isDirectory())) {
      const samplePath = path.join(artifactsDir, sampleDir.name)
      const files = await fs.readdir(samplePath, { withFileTypes: true }).catch(() => [])
      
      for (const file of files.filter(f => f.isFile())) {
        const filePath = path.join(samplePath, file.name)
        const stats = await fs.stat(filePath).catch(() => null)
        if (stats) {
          // Use file mtime to determine bucket
          const mtime = new Date(stats.mtime)
          const daysOld = Math.floor((now.getTime() - mtime.getTime()) / (1000 * 60 * 60 * 24))
          
          let bucket: keyof typeof buckets
          if (daysOld <= activeDays) {
            bucket = 'active'
          } else if (daysOld <= recentDays) {
            bucket = 'recent'
          } else {
            bucket = 'archive'
          }
          
          buckets[bucket].artifactCount++
          buckets[bucket].totalBytes += stats.size
        }
      }
    }

    // Format report
    const formatBucket = (name: keyof typeof buckets) => ({
      name,
      sampleCount: buckets[name].sampleCount,
      artifactCount: buckets[name].artifactCount,
      totalBytes: buckets[name].totalBytes,
      oldestDate: buckets[name].dates.sort()[0] || null,
      newestDate: buckets[name].dates.sort().reverse()[0] || null,
    })

    const cleanupEstimate = buckets.archive.totalBytes

    return {
      buckets: ['active', 'recent', 'archive'].map(b => formatBucket(b as keyof typeof buckets)),
      totalBytes: Object.values(buckets).reduce((sum, b) => sum + b.totalBytes, 0),
      cleanupEstimate,
    }
  }

  /**
   * Apply retention policy and delete old samples/artifacts
   */
  async applyRetention(options?: {
    dryRun?: boolean
    maxAgeDays?: number
    bucket?: 'active' | 'recent' | 'archive'
  }): Promise<{
    status: 'complete' | 'partial' | 'failed'
    deletedSamples: number
    deletedArtifacts: number
    freedBytes: number
    errors: Array<{ path: string; error: string }>
  }> {
    const dryRun = options?.dryRun ?? false
    const maxAgeDays = options?.maxAgeDays ?? this.config.retentionDays
    const targetBucket = options?.bucket
    
    const now = new Date()
    const deletedSamples: number[] = []
    const deletedArtifacts: number[] = []
    let freedBytes = 0
    const errors: Array<{ path: string; error: string }> = []

    // Delete old samples
    const samplesDir = path.join(this.config.root, 'samples')
    const dateDirs = await fs.readdir(samplesDir, { withFileTypes: true }).catch(() => [])
    
    for (const dateDir of dateDirs.filter(d => d.isDirectory())) {
      const dateStr = dateDir.name
      const date = new Date(dateStr)
      const daysOld = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24))
      
      if (daysOld <= maxAgeDays) {
        continue
      }

      // Check if this falls in target bucket
      const bucket = daysOld <= 7 ? 'active' : daysOld <= 30 ? 'recent' : 'archive'
      if (targetBucket && bucket !== targetBucket) {
        continue
      }

      const datePath = path.join(samplesDir, dateDir.name)
      const files = await fs.readdir(datePath)
      
      for (const file of files) {
        const filePath = path.join(datePath, file)
        const stats = await fs.stat(filePath).catch(() => null)
        
        if (stats) {
          if (dryRun) {
            freedBytes += stats.size
            deletedSamples.push(stats.size)
          } else {
            try {
              await fs.unlink(filePath)
              freedBytes += stats.size
              deletedSamples.push(stats.size)
              logger.info(`Retention deleted sample: ${filePath}`)
            } catch (error: any) {
              errors.push({ path: filePath, error: error.message })
            }
          }
        }
      }
    }

    // Delete old artifacts
    const artifactsDir = path.join(this.config.root, 'artifacts')
    const sampleDirs = await fs.readdir(artifactsDir, { withFileTypes: true }).catch(() => [])
    
    for (const sampleDir of sampleDirs.filter(d => d.isDirectory())) {
      const samplePath = path.join(artifactsDir, sampleDir.name)
      const files = await fs.readdir(samplePath, { withFileTypes: true }).catch(() => [])
      
      for (const file of files.filter(f => f.isFile())) {
        const filePath = path.join(samplePath, file.name)
        const stats = await fs.stat(filePath).catch(() => null)
        
        if (stats) {
          const mtime = new Date(stats.mtime)
          const daysOld = Math.floor((now.getTime() - mtime.getTime()) / (1000 * 60 * 60 * 24))
          
          if (daysOld <= maxAgeDays) {
            continue
          }

          const bucket = daysOld <= 7 ? 'active' : daysOld <= 30 ? 'recent' : 'archive'
          if (targetBucket && bucket !== targetBucket) {
            continue
          }

          if (dryRun) {
            freedBytes += stats.size
            deletedArtifacts.push(stats.size)
          } else {
            try {
              await fs.unlink(filePath)
              freedBytes += stats.size
              deletedArtifacts.push(stats.size)
              logger.info(`Retention deleted artifact: ${filePath}`)
            } catch (error: any) {
              errors.push({ path: filePath, error: error.message })
            }
          }
        }
      }
    }

    const status = errors.length === 0 ? 'complete' : errors.length < (deletedSamples.length + deletedArtifacts.length) ? 'partial' : 'failed'

    return {
      status,
      deletedSamples: deletedSamples.length,
      deletedArtifacts: deletedArtifacts.length,
      freedBytes,
      errors,
    }
  }
}
