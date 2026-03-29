/**
 * sample.ingest tool implementation
 * Uploads and registers new samples to the system
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */

import { z } from 'zod'
import fs from 'fs'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { PolicyGuard } from '../policy-guard.js'
import { withLogging, logError, logWarning } from '../logger.js'
import {
  MAX_SAMPLE_SIZE,
  createSampleFinalizationService,
} from '../sample-finalization.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for sample.ingest tool
 * Requirements: 1.1
 */
export const SampleIngestInputSchema = z
  .object({
    path: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe('Preferred for local files. Pass an absolute local file path when the MCP client can access the file system.'),
    bytes_b64: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe('Fallback only. Use Base64 file bytes when the MCP client cannot access the local file path. Ignored when `path` is provided.'),
    // NEW: API upload support
    upload_url: z
      .string()
      .url()
      .optional()
      .describe('Compatibility-only path for daemon-backed upload sessions. Prefer reading `sample_id` directly from the upload response and only pass `upload_url` here when an older client still expects the extra finalize step.'),
    api_key: z
      .string()
      .optional()
      .describe('Legacy compatibility field. Not required for daemon-backed upload-session lookup.'),
    filename: z.string().optional().describe('Optional display/original filename'),
    source: z.string().optional().describe('Optional source tag, e.g. upload/email/sandbox'),
  })
  .superRefine((value, ctx) => {
    const hasPath = typeof value.path === 'string' && value.path.length > 0
    const hasBytes = typeof value.bytes_b64 === 'string' && value.bytes_b64.length > 0
    const hasUploadUrl = typeof value.upload_url === 'string' && value.upload_url.length > 0

    if (!hasPath && !hasBytes && !hasUploadUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['path'],
        message: 'Provide either `path` (preferred for local files), `bytes_b64` (fallback), or `upload_url` (HTTP API upload).',
      })
    }
  })
  .describe('Ingest a sample from a local file path, Base64 bytes, or HTTP API upload. Prefer `path` whenever the MCP client can access the file directly.')

export type SampleIngestInput = z.infer<typeof SampleIngestInputSchema>

/**
 * Output schema for sample.ingest tool
 * Requirements: 1.5
 */
export const SampleIngestOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string(),
    size: z.number(),
    file_type: z.string().optional(),
    existed: z.boolean().optional(),
    result_mode: z.literal('sample_registered'),
    tool_surface_role: ToolSurfaceRoleSchema,
    preferred_primary_tools: z.array(z.string()),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
})

export type SampleIngestOutput = z.infer<typeof SampleIngestOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for sample.ingest
 */
export const sampleIngestToolDefinition: ToolDefinition = {
  name: 'sample.ingest',
  description:
    'Register a sample from exactly one ingest path: a container-visible local file path, Base64 bytes, or a compatibility upload_url. ' +
    'Use this tool when the MCP worker can already read the file path directly or when a small file must be sent as Base64. ' +
    'Do not use path for host-machine files that only exist outside the container; use sample.request_upload instead. ' +
    '\n\nDecision guide:\n' +
    '- Use when: the file is already accessible to the MCP worker, or a small Base64 fallback is required.\n' +
    '- Do not use when: the only copy is on the host machine outside the container-accessible filesystem.\n' +
    '- Typical next step: continue with workflow.analyze.start for the staged-runtime path, or use workflow.triage only when you explicitly want the compatibility quick-profile surface.\n' +
    '- Common mistake: passing a Windows host path to path while the MCP worker is running inside Docker.\n' +
    '\nPrimary host-file workflow:\n' +
    '1. Call sample.request_upload.\n' +
    '2. POST the file bytes to upload_url.\n' +
    '3. Read sample_id from the HTTP upload response.\n' +
    '\nCompatibility-only workflow:\n' +
    'Call sample.ingest(upload_url) only when a legacy client still requires an extra finalize step after upload.',
  inputSchema: SampleIngestInputSchema,
  outputSchema: SampleIngestOutputSchema,
}

// ============================================================================
// Helper Functions
// ============================================================================

function extractUploadToken(uploadUrl: string): string | null {
  const url = new URL(uploadUrl)
  const queryToken = url.searchParams.get('token')
  if (queryToken) {
    return queryToken
  }

  const parts = url.pathname.split('/').filter(Boolean)
  if (parts.length === 0) {
    return null
  }

  if (parts[parts.length - 1] === 'status' && parts.length >= 2) {
    return parts[parts.length - 2]
  }

  return parts[parts.length - 1] || null
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create sample.ingest tool handler
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */
export function createSampleIngestHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard
) {
  const finalizationService = createSampleFinalizationService(
    workspaceManager,
    database,
    policyGuard
  )

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as SampleIngestInput

    return withLogging(
      {
        operation: 'sample.ingest',
        toolName: 'sample.ingest',
        source: input.source,
      },
      async () => {
        try {
          // 1. Read sample data
          let data: Buffer
          let originalFilename: string

          if (input.path) {
            // Read from file path
            if (!fs.existsSync(input.path)) {
              logWarning('File not found', { path: input.path })
              return {
                ok: false,
                errors: [`File not found: ${input.path}`],
              }
            }

            data = fs.readFileSync(input.path)
            // Extract just the filename, not the full path
            const pathParts = input.path.replace(/\\/g, '/').split('/')
            originalFilename = input.filename || pathParts[pathParts.length - 1] || 'sample.bin'
          } else if (input.upload_url) {
            const token = extractUploadToken(input.upload_url)

            if (!token) {
              return {
                ok: false,
                errors: ['Invalid upload_url: missing upload session token'],
              }
            }

            database.expireUploadSessions()
            const session = database.findUploadSessionByToken(token)
            if (!session) {
              return {
                ok: false,
                errors: ['Invalid or expired upload session'],
              }
            }

            if (
              session.status !== 'registered' &&
              new Date(session.expires_at).getTime() < Date.now()
            ) {
              database.markUploadSessionExpired(token)
              return {
                ok: false,
                errors: ['Upload session expired'],
              }
            }

            if (session.status === 'failed') {
              return {
                ok: false,
                errors: [session.error || 'Upload session failed'],
              }
            }

            if (session.status === 'expired') {
              return {
                ok: false,
                errors: ['Upload session expired'],
              }
            }

            if (session.status === 'registered' && session.sample_id) {
              const existingSample = database.findSample(session.sample_id)
              return {
                ok: true,
                data: {
                  sample_id: session.sample_id,
                  size: existingSample?.size || session.size || 0,
                  file_type: existingSample?.file_type || undefined,
                  existed: true,
                  result_mode: 'sample_registered',
                  tool_surface_role: 'primary',
                  preferred_primary_tools: ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
                  recommended_next_tools: ['workflow.analyze.start', 'workflow.summarize', 'workflow.triage'],
                  next_actions: [
                    'Use workflow.analyze.start with the returned sample_id for the primary staged-runtime path.',
                    'Use workflow.triage only when you intentionally want the compatibility quick-profile surface.',
                    'Promote the staged run or call workflow.summarize after deeper analysis has persisted.',
                  ],
                },
              }
            }

            if (session.status !== 'uploaded' || !session.staged_path) {
              return {
                ok: false,
                errors: ['File not yet uploaded to the upload endpoint'],
              }
            }

            if (!fs.existsSync(session.staged_path)) {
              return {
                ok: false,
                errors: [`Uploaded file not found: ${session.staged_path}`],
              }
            }

            data = fs.readFileSync(session.staged_path)
            originalFilename = input.filename || session.filename || 'sample.bin'

            try {
              const finalized = await finalizationService.finalizeBuffer({
                data,
                filename: originalFilename,
                source: input.source || session.source || 'api_upload',
                auditOperation: 'sample.ingest',
              })

              database.markUploadSessionRegistered(token, {
                sample_id: finalized.sample_id,
                size: finalized.size,
                sha256: finalized.sha256,
                md5: finalized.md5,
                clearStagedPath: true,
              })

              try {
                fs.unlinkSync(session.staged_path)
              } catch (error) {
                logWarning('Failed to clean up uploaded file', { path: session.staged_path })
              }

              return {
                ok: true,
                data: {
                  sample_id: finalized.sample_id,
                  size: finalized.size,
                  file_type: finalized.file_type,
                  existed: finalized.existed,
                  result_mode: 'sample_registered',
                  tool_surface_role: 'primary',
                  preferred_primary_tools: ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
                  recommended_next_tools: ['workflow.analyze.start', 'workflow.summarize', 'workflow.triage'],
                  next_actions: [
                    'Use workflow.analyze.start with the returned sample_id for the primary staged-runtime path.',
                    'Use workflow.triage only when you intentionally want the compatibility quick-profile surface.',
                    'Promote the staged run or call workflow.summarize after deeper analysis has persisted.',
                  ],
                },
              }
            } catch (error) {
              database.markUploadSessionFailed(token, (error as Error).message)
              throw error
            }
          } else if (input.bytes_b64) {
            // Decode from Base64
            // Validate Base64 format first
            const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/
            if (!base64Regex.test(input.bytes_b64)) {
              logWarning('Invalid Base64 encoding', { length: input.bytes_b64.length })
              return {
                ok: false,
                errors: ['Invalid Base64 encoding: contains invalid characters'],
              }
            }

            try {
              data = Buffer.from(input.bytes_b64, 'base64')
              // Verify the decoded data is not empty and makes sense
              if (data.length === 0 && input.bytes_b64.length > 0) {
                throw new Error('Base64 decoding resulted in empty buffer')
              }
            } catch (error) {
              logError(error as Error, { operation: 'base64_decode' })
              return {
                ok: false,
                errors: [`Invalid Base64 encoding: ${(error as Error).message}`],
              }
            }
            originalFilename = input.filename || 'sample.bin'
          } else {
            return {
              ok: false,
              errors: [
                'Missing input: provide `path` (preferred local file path) or `bytes_b64` (Base64 bytes fallback when the client cannot access the file path).',
              ],
            }
          }

          // 2. Check file size limit
          // Requirement: 1.3
          if (data.length > MAX_SAMPLE_SIZE) {
            logWarning('Sample size exceeds limit', {
              size: data.length,
              maxSize: MAX_SAMPLE_SIZE,
            })
            return {
              ok: false,
              errors: [
                `Sample size ${data.length} bytes exceeds maximum limit of ${MAX_SAMPLE_SIZE} bytes (500MB)`
              ],
            }
          }

          const finalized = await finalizationService.finalizeBuffer({
            data,
            filename: originalFilename,
            source: input.source || 'upload',
            auditOperation: 'sample.ingest',
          })

          return {
            ok: true,
            data: {
              sample_id: finalized.sample_id,
              size: finalized.size,
              file_type: finalized.file_type,
              existed: finalized.existed,
              result_mode: 'sample_registered',
              tool_surface_role: 'primary',
              preferred_primary_tools: ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
              recommended_next_tools: ['workflow.analyze.start', 'workflow.summarize', 'workflow.triage'],
              next_actions: [
                'Use workflow.analyze.start with the returned sample_id for the primary staged-runtime path.',
                'Use workflow.triage only when you intentionally want the compatibility quick-profile surface.',
                'Promote the staged run or call workflow.summarize after deeper analysis has persisted.',
              ],
            },
          }
        } catch (error) {
          logError(error as Error, { operation: 'sample.ingest' })
          return {
            ok: false,
            errors: [(error as Error).message],
          }
        }
      }
    )
  }
}
