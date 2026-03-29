/**
 * Metadata Logger
 * Logs file upload metadata for auditing and tracking
 */

import fs from 'fs/promises'
import path from 'path'
import { logger } from '../logger.js'

export interface UploadMetadata {
  timestamp: string
  sha256: string
  filename: string
  size: number
  source?: string
  uploadedBy?: string
  storagePath: string
}

export interface MetadataLoggerConfig {
  storageRoot: string
}

export class MetadataLogger {
  private config: MetadataLoggerConfig
  private logPath: string

  constructor(config: MetadataLoggerConfig) {
    this.config = config
    this.logPath = path.join(config.storageRoot, '.metadata', 'uploads.jsonl')
  }

  /**
   * Initialize metadata logger
   */
  async initialize(): Promise<void> {
    const metadataDir = path.join(this.config.storageRoot, '.metadata')
    await fs.mkdir(metadataDir, { recursive: true })

    // Create log file if it doesn't exist
    try {
      await fs.access(this.logPath)
    } catch {
      await fs.writeFile(this.logPath, '', 'utf8')
    }

    logger.info(`Metadata logger initialized: ${this.logPath}`)
  }

  /**
   * Log upload metadata
   */
  async logUpload(metadata: UploadMetadata): Promise<void> {
    try {
      const line = JSON.stringify(metadata) + '\n'
      await fs.appendFile(this.logPath, line, 'utf8')
      logger.debug(`Logged upload metadata: ${metadata.sha256}`)
    } catch (error) {
      logger.error('Failed to log upload metadata: ' + JSON.stringify(error))
    }
  }

  /**
   * Query upload history
   */
  async queryHistory(options?: {
    fromDate?: Date
    toDate?: Date
    sha256?: string
    limit?: number
  }): Promise<UploadMetadata[]> {
    try {
      const content = await fs.readFile(this.logPath, 'utf8')
      const lines = content.trim().split('\n').filter(line => line.trim())
      const records: UploadMetadata[] = []

      for (const line of lines) {
        try {
          const record = JSON.parse(line) as UploadMetadata

          // Apply filters
          if (options?.fromDate && new Date(record.timestamp) < options.fromDate) {
            continue
          }
          if (options?.toDate && new Date(record.timestamp) > options.toDate) {
            continue
          }
          if (options?.sha256 && record.sha256 !== options.sha256) {
            continue
          }

          records.push(record)

          // Apply limit
          if (options?.limit && records.length >= options.limit) {
            break
          }
        } catch (error) {
          logger.warn('Failed to parse log line: ' + JSON.stringify(error))
        }
      }

      return records
    } catch (error) {
      logger.error('Failed to query upload history: ' + JSON.stringify(error))
      return []
    }
  }

  /**
   * Get upload statistics
   */
  async getStats(): Promise<{
    totalUploads: number
    totalSize: number
    uploadsByDate: Record<string, number>
  }> {
    const history = await this.queryHistory()

    const stats = {
      totalUploads: history.length,
      totalSize: history.reduce((sum, record) => sum + record.size, 0),
      uploadsByDate: {} as Record<string, number>,
    }

    for (const record of history) {
      const date = record.timestamp.split('T')[0]
      stats.uploadsByDate[date] = (stats.uploadsByDate[date] || 0) + 1
    }

    return stats
  }
}
