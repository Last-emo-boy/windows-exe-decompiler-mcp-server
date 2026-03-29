/**
 * artifact.download tool - Download artifact by ID
 * Tasks: api-file-server 2.4, 6.2
 */

import { z } from 'zod'
import fs from 'fs/promises'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { WorkspaceManager } from '../workspace-manager.js'

const TOOL_NAME = 'artifact.download'
const TOOL_VERSION = '0.1.0'

export const ArtifactDownloadInputSchema = z.object({
  artifact_id: z.string().describe('Artifact ID'),
  include_content: z.boolean().default(false).describe('Whether to include artifact content (for JSON artifacts)'),
  sample_id: z.string().optional().describe('Optional sample ID for context'),
})

export const ArtifactDownloadOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    artifact_id: z.string(),
    sample_id: z.string(),
    type: z.string(),
    path: z.string(),
    sha256: z.string(),
    mime: z.string().optional(),
    created_at: z.string(),
    size: z.number().optional(),
    download_url: z.string().describe('HTTP API download URL'),
    content: z.unknown().optional().describe('Parsed JSON content if include_content=true and artifact is JSON'),
  }).optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

export type ArtifactDownloadInput = z.infer<typeof ArtifactDownloadInputSchema>

export const artifactDownloadToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Download an artifact by ID. Returns artifact metadata and download URL. ' +
    'Use this to retrieve analysis artifacts such as reports, summaries, or exported files. ' +
    'For JSON artifacts, you can optionally include the parsed content in the response. ' +
    '\n\nDecision guide:\n' +
    '- Use when: You need to access a specific artifact from a previous analysis.\n' +
    '- Do not use when: You want a summary of all artifacts (use artifacts.list instead).\n' +
    '- Typical next step: Use the download_url to fetch the file, or read content directly if JSON.\n' +
    '- Common mistake: Artifact IDs are UUIDs, not sample IDs.',
  inputSchema: ArtifactDownloadInputSchema,
  outputSchema: ArtifactDownloadOutputSchema,
}

interface ArtifactDownloadDependencies {
  storageManager?: StorageManager
  workspaceManager?: WorkspaceManager
}

export function createArtifactDownloadHandler(
  database: DatabaseManager,
  dependencies: ArtifactDownloadDependencies = {}
) {
  const storageManager = dependencies.storageManager
  const workspaceManager = dependencies.workspaceManager

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = ArtifactDownloadInputSchema.parse(args)
      const artifact = database.findArtifact(input.artifact_id)

      if (!artifact) {
        return {
          ok: false,
          errors: [`Artifact not found: ${input.artifact_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Validate sample_id if provided
      if (input.sample_id && artifact.sample_id !== input.sample_id) {
        return {
          ok: false,
          errors: [`Artifact ${input.artifact_id} does not belong to sample ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Get file size if storage manager available
      let size: number | undefined
      if (workspaceManager) {
        try {
          const workspace = await workspaceManager.getWorkspace(artifact.sample_id)
          const artifactPath = workspaceManager.normalizePath(workspace.root, artifact.path)
          const stat = await fs.stat(artifactPath)
          size = stat.size
        } catch {
          // Size unavailable, continue
        }
      } else if (storageManager) {
        try {
          const content = await storageManager.retrieveArtifact(artifact.path)
          if (content) {
            size = content.length
          }
        } catch {
          // Size unavailable, continue
        }
      }

      // Build download URL
      const apiPort = process.env.API_PORT || '18080'
      const downloadUrl = `http://localhost:${apiPort}/api/v1/artifacts/${encodeURIComponent(input.artifact_id)}?download=true`

      // Optionally include content for JSON artifacts
      let content: unknown
      if (input.include_content && artifact.mime?.includes('application/json')) {
        try {
          if (workspaceManager) {
            const workspace = await workspaceManager.getWorkspace(artifact.sample_id)
            const artifactPath = workspaceManager.normalizePath(workspace.root, artifact.path)
            const buffer = await fs.readFile(artifactPath)
            content = JSON.parse(buffer.toString('utf8'))
          } else if (storageManager) {
            const buffer = await storageManager.retrieveArtifact(artifact.path)
            if (buffer) {
              content = JSON.parse(buffer.toString('utf8'))
            }
          }
        } catch (error) {
          // Content unavailable, continue without it
        }
      }

      const data = {
        artifact_id: artifact.id,
        sample_id: artifact.sample_id,
        type: artifact.type,
        path: artifact.path,
        sha256: artifact.sha256,
        mime: artifact.mime,
        created_at: artifact.created_at,
        size,
        download_url: downloadUrl,
        content,
      }

      return {
        ok: true,
        data,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
