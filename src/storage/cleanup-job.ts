/**
 * Storage Cleanup Job
 * Automatically cleans up old files based on retention policy
 */

import fs from 'fs/promises'
import path from 'path'
import { logger } from '../logger.js'
import { DatabaseManager } from '../database.js'

export interface CleanupConfig {
  storageRoot: string
  retentionDays: number
  dryRun?: boolean
  databasePath?: string
}

export interface CleanupResult {
  deletedFiles: string[]
  deletedBytes: number
  errors: string[]
}

/**
 * Run cleanup job
 */
export async function runCleanup(config: CleanupConfig): Promise<CleanupResult> {
  const result: CleanupResult = {
    deletedFiles: [],
    deletedBytes: 0,
    errors: [],
  }

  const cutoffDate = new Date()
  cutoffDate.setDate(cutoffDate.getDate() - config.retentionDays)

  logger.info(`Starting cleanup job (retention: ${config.retentionDays} days, cutoff: ${cutoffDate.toISOString()})`)

  try {
    if (config.databasePath) {
      const database = new DatabaseManager(config.databasePath)
      try {
        database.expireUploadSessions()
      } finally {
        database.close()
      }
    }

    // Clean samples
    const samplesDir = path.join(config.storageRoot, 'samples')
    const samplesResult = await cleanDirectory(samplesDir, cutoffDate, config.dryRun || false)
    result.deletedFiles.push(...samplesResult.deletedFiles)
    result.deletedBytes += samplesResult.deletedBytes
    result.errors.push(...samplesResult.errors)

    // Clean uploads (temporary storage)
    const uploadsDir = path.join(config.storageRoot, 'uploads')
    const uploadsResult = await cleanDirectory(uploadsDir, cutoffDate, config.dryRun || false)
    result.deletedFiles.push(...uploadsResult.deletedFiles)
    result.deletedBytes += uploadsResult.deletedBytes
    result.errors.push(...uploadsResult.errors)

    logger.info(`Cleanup complete: ${result.deletedFiles.length} files deleted, ${formatBytes(result.deletedBytes)} freed`)

    return result
  } catch (error) {
    logger.error('Cleanup job failed: ' + JSON.stringify(error))
    result.errors.push((error as Error).message)
    return result
  }
}

/**
 * Clean directory recursively
 */
async function cleanDirectory(
  dir: string,
  cutoffDate: Date,
  dryRun: boolean
): Promise<{ deletedFiles: string[]; deletedBytes: number; errors: string[] }> {
  const result = {
    deletedFiles: [] as string[],
    deletedBytes: 0,
    errors: [] as string[],
  }

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)

      if (entry.isDirectory()) {
        // Check if directory name is a date (YYYY-MM-DD format)
        const dateMatch = entry.name.match(/^\d{4}-\d{2}-\d{2}$/)
        if (dateMatch) {
          const dirDate = new Date(entry.name)
          if (dirDate < cutoffDate) {
            // Delete entire directory
            if (dryRun) {
              logger.info(`[DRY RUN] Would delete directory: ${fullPath}`)
            } else {
              await fs.rm(fullPath, { recursive: true, force: true })
              logger.info(`Deleted directory: ${fullPath}`)
            }
            result.deletedFiles.push(fullPath)
          } else {
            // Recursively clean subdirectory
            const subResult = await cleanDirectory(fullPath, cutoffDate, dryRun)
            result.deletedFiles.push(...subResult.deletedFiles)
            result.deletedBytes += subResult.deletedBytes
            result.errors.push(...subResult.errors)
          }
        }
      } else if (entry.isFile()) {
        const stats = await fs.stat(fullPath)
        const fileDate = new Date(stats.mtime)

        if (fileDate < cutoffDate) {
          if (dryRun) {
            logger.info(`[DRY RUN] Would delete file: ${fullPath}`)
          } else {
            await fs.unlink(fullPath)
            logger.info(`Deleted file: ${fullPath}`)
          }
          result.deletedFiles.push(fullPath)
          result.deletedBytes += stats.size
        }
      }
    }
  } catch (error) {
    logger.error('Error cleaning directory ' + dir + ': ' + JSON.stringify(error))
    result.errors.push((error as Error).message)
  }

  return result
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

/**
 * Schedule daily cleanup job
 */
export function scheduleDailyCleanup(
  config: CleanupConfig,
  hour: number = 3  // 3 AM by default
): NodeJS.Timeout {
  const now = new Date()
  const nextRun = new Date(now)
  nextRun.setHours(hour, 0, 0, 0)

  if (nextRun <= now) {
    nextRun.setDate(nextRun.getDate() + 1)
  }

  const delay = nextRun.getTime() - now.getTime()

  logger.info(`Next cleanup scheduled for ${nextRun.toISOString()} (in ${Math.round(delay / 1000 / 60)} minutes)`)

  return setTimeout(() => {
    runCleanup(config)
      .then(() => {
        // Schedule next run
        scheduleDailyCleanup(config, hour)
      })
      .catch((error) => {
        logger.error('Scheduled cleanup failed: ' + JSON.stringify(error))
        // Still schedule next run
        scheduleDailyCleanup(config, hour)
      })
  }, delay)
}
