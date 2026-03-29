import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import type { PolicyGuard } from './policy-guard.js'
import { logWarning } from './logger.js'

export const MAX_SAMPLE_SIZE = 500 * 1024 * 1024

export interface FinalizeSampleInput {
  data: Buffer
  filename?: string
  source?: string
  auditOperation?: string
}

export interface FinalizeSampleResult {
  sample_id: string
  size: number
  file_type: string
  existed?: boolean
  sha256: string
  md5: string
}

function computeSHA256(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

function computeMD5(data: Buffer): string {
  return crypto.createHash('md5').update(data).digest('hex')
}

export function detectFileType(data: Buffer): string {
  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
    return 'PE'
  }

  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46
  ) {
    return 'ELF'
  }

  return 'unknown'
}

function normalizeFilename(filename?: string): string {
  const candidate = typeof filename === 'string' ? filename.replace(/\\/g, '/') : ''
  const basename = path.posix.basename(candidate || 'sample.bin').trim()
  return basename.length > 0 ? basename : 'sample.bin'
}

export class SampleFinalizationService {
  constructor(
    private readonly workspaceManager: WorkspaceManager,
    private readonly database: DatabaseManager,
    private readonly policyGuard: PolicyGuard
  ) {}

  async finalizeBuffer(input: FinalizeSampleInput): Promise<FinalizeSampleResult> {
    if (input.data.length > MAX_SAMPLE_SIZE) {
      throw new Error(
        `Sample size ${input.data.length} bytes exceeds maximum limit of ${MAX_SAMPLE_SIZE} bytes (500MB)`
      )
    }

    const sha256 = computeSHA256(input.data)
    const md5 = computeMD5(input.data)
    const sampleId = `sha256:${sha256}`
    const source = input.source || 'upload'
    const filename = normalizeFilename(input.filename)
    const existingSample = this.database.findSampleBySha256(sha256)

    if (existingSample) {
      await this.policyGuard.auditLog({
        timestamp: new Date().toISOString(),
        operation: input.auditOperation || 'sample.ingest',
        sampleId: existingSample.id,
        decision: 'allow',
        reason: 'Sample already exists (SHA256 match)',
        metadata: {
          size: input.data.length,
          source,
          existed: true,
        },
      })

      return {
        sample_id: existingSample.id,
        size: existingSample.size,
        file_type: existingSample.file_type || 'unknown',
        existed: true,
        sha256,
        md5,
      }
    }

    const workspace = await this.workspaceManager.createWorkspace(sampleId)
    const samplePath = path.join(workspace.original, filename)
    fs.writeFileSync(samplePath, input.data)

    try {
      fs.chmodSync(samplePath, 0o444)
    } catch (error) {
      logWarning('Failed to set file permissions', {
        path: samplePath,
        error: (error as Error).message,
      })
    }

    const fileType = detectFileType(input.data)
    const sample = {
      id: sampleId,
      sha256,
      md5,
      size: input.data.length,
      file_type: fileType,
      created_at: new Date().toISOString(),
      source,
    }

    try {
      this.database.insertSample(sample)
    } catch (error: any) {
      if (
        error.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
        error.message?.includes('UNIQUE constraint')
      ) {
        const concurrentSample = this.database.findSampleBySha256(sha256)
        if (concurrentSample) {
          await this.policyGuard.auditLog({
            timestamp: new Date().toISOString(),
            operation: input.auditOperation || 'sample.ingest',
            sampleId: concurrentSample.id,
            decision: 'allow',
            reason: 'Sample already exists (concurrent insert race condition)',
            metadata: {
              size: input.data.length,
              source,
              existed: true,
            },
          })

          return {
            sample_id: concurrentSample.id,
            size: concurrentSample.size,
            file_type: concurrentSample.file_type || 'unknown',
            existed: true,
            sha256,
            md5,
          }
        }
      }

      throw error
    }

    await this.policyGuard.auditLog({
      timestamp: new Date().toISOString(),
      operation: input.auditOperation || 'sample.ingest',
      sampleId: sample.id,
      decision: 'allow',
      metadata: {
        size: input.data.length,
        source,
        file_type: fileType,
      },
    })

    return {
      sample_id: sampleId,
      size: input.data.length,
      file_type: fileType,
      sha256,
      md5,
    }
  }
}

export function createSampleFinalizationService(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard
): SampleFinalizationService {
  return new SampleFinalizationService(workspaceManager, database, policyGuard)
}
