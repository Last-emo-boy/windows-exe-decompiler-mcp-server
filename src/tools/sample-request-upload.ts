/**
 * sample.request_upload tool
 * Creates a durable upload session backed by the daemon-owned HTTP file server.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

export const SampleRequestUploadInputSchema = z.object({
  filename: z.string().optional().describe('Original filename'),
  ttl_seconds: z.number().int().min(30).max(3600).default(300).describe('Token TTL in seconds'),
})

export const SampleRequestUploadOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    upload_url: z.string().url(),
    status_url: z.string().url().optional(),
    token: z.string(),
    expires_at: z.string(),
    ttl_seconds: z.number(),
    result_mode: z.literal('upload_session'),
    tool_surface_role: ToolSurfaceRoleSchema,
    preferred_primary_tools: z.array(z.string()),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
})

export const sampleRequestUploadToolDefinition: ToolDefinition = {
  name: 'sample.request_upload',
  description:
    'Primary host-file upload entrypoint. Use this when the sample file is on the HOST machine and the MCP worker cannot read that path directly. ' +
    'Do not use this for files that already exist inside the container-accessible filesystem; use sample.ingest(path) instead. ' +
    'The returned daemon-backed upload URL stays valid across MCP worker process boundaries. ' +
    '\n\nDecision guide:\n' +
    '- Use when: the sample is on the host machine and must be uploaded over HTTP.\n' +
    '- Do not use when: the file is already readable by the MCP server inside the container or shared filesystem.\n' +
    '- Typical next step: POST the raw file bytes to upload_url, read sample_id from the HTTP response, then call workflow.triage, ghidra.analyze, or workflow.reconstruct.\n' +
    '- Common mistake: calling sample.ingest(path=\"C:\\\\host\\\\file.exe\") from a containerized MCP worker.\n' +
    '\nUpload contract:\n' +
    '1. Use HTTP POST (not PUT, not GET).\n' +
    '2. Send Content-Type: application/octet-stream.\n' +
    '3. Read sample_id directly from the upload response.\n' +
    '4. Only call sample.ingest(upload_url) for legacy compatibility clients that still require an extra finalize step.',
  inputSchema: SampleRequestUploadInputSchema,
  outputSchema: SampleRequestUploadOutputSchema,
}

export interface SampleRequestUploadOptions {
  apiPort?: number
  baseUrl?: string
}

function buildBaseUrl(options?: SampleRequestUploadOptions): string {
  if (options?.baseUrl && options.baseUrl.trim().length > 0) {
    return options.baseUrl.replace(/\/+$/, '')
  }

  return `http://localhost:${options?.apiPort || 18080}`
}

export function createSampleRequestUploadHandler(
  database: DatabaseManager,
  options?: SampleRequestUploadOptions
) {
  const baseUrl = buildBaseUrl(options)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = args as z.infer<typeof SampleRequestUploadInputSchema>
      const expiresAt = new Date(Date.now() + (input.ttl_seconds || 300) * 1000).toISOString()
      const session = database.createUploadSession({
        filename: input.filename || null,
        source: 'mcp_upload',
        expires_at: expiresAt,
      })

      return {
        ok: true,
        data: {
          upload_url: `${baseUrl}/api/v1/uploads/${session.token}`,
          status_url: `${baseUrl}/api/v1/uploads/${session.token}/status`,
          token: session.token,
          expires_at: session.expires_at,
          ttl_seconds: input.ttl_seconds || 300,
          result_mode: 'upload_session',
          tool_surface_role: 'primary',
          preferred_primary_tools: ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
          recommended_next_tools: ['workflow.analyze.start', 'workflow.summarize', 'workflow.triage'],
          next_actions: [
            'POST the file bytes to upload_url with Content-Type: application/octet-stream.',
            'Read sample_id from the HTTP upload response instead of calling another MCP tool first.',
            'Use that sample_id with workflow.analyze.start for the primary staged-runtime path, or workflow.triage only when you explicitly want the compatibility quick-profile surface.',
            'Only use sample.ingest(upload_url) if a legacy client still expects the extra finalize step.',
          ],
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`Failed to create upload session: ${(error as Error).message}`],
      }
    }
  }
}
