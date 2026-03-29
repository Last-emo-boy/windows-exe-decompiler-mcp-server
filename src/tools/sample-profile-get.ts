/**
 * sample.profile.get tool implementation
 * Retrieves sample profile including basic information, completed analyses,
 * and workspace/original integrity status.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import { inspectSampleWorkspace } from '../sample-workspace.js'

const DEFAULT_ANALYSIS_DETAIL = 'compact' as const
const DEFAULT_MAX_ANALYSES = 25
const DEFAULT_JSON_PREVIEW_CHARS = 2048
const DEFAULT_WORKSPACE_FILE_PREVIEW_LIMIT = 16

export const SampleProfileGetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe('Optional stale-analysis reap threshold in milliseconds. Omit or null to disable auto-reaping.'),
  analysis_detail: z
    .enum(['compact', 'full'])
    .default(DEFAULT_ANALYSIS_DETAIL)
    .describe(
      'compact is the default bounded mode and returns preview snippets plus byte counts for analysis output. full returns full output_json/metrics_json for the returned analyses and is intended for targeted debugging only.'
    ),
  max_analyses: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(DEFAULT_MAX_ANALYSES)
    .describe('Maximum number of analyses to return inline. Most recent analyses are returned first.'),
  json_preview_chars: z
    .number()
    .int()
    .min(128)
    .max(20000)
    .default(DEFAULT_JSON_PREVIEW_CHARS)
    .describe('Maximum number of characters to inline for each analysis output/metrics preview when analysis_detail=compact.'),
  workspace_file_preview_limit: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(DEFAULT_WORKSPACE_FILE_PREVIEW_LIMIT)
    .describe('Maximum number of filenames to inline from workspace/original and alternate original directories.'),
})

export type SampleProfileGetInput = z.infer<typeof SampleProfileGetInputSchema>

export const SampleProfileGetOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample: z.object({
        id: z.string(),
        sha256: z.string(),
        md5: z.string(),
        size: z.number(),
        file_type: z.string().optional(),
        created_at: z.string(),
        source: z.string(),
      }),
      analysis_summary: z.object({
        detail: z.enum(['compact', 'full']),
        total_count: z.number().int().nonnegative(),
        returned_count: z.number().int().nonnegative(),
        analyses_truncated: z.boolean(),
        json_preview_chars: z.number().int().positive(),
      }),
      analyses: z.array(
        z.object({
          id: z.string(),
          stage: z.string(),
          backend: z.string(),
          status: z.string(),
          started_at: z.string().optional(),
          finished_at: z.string().optional(),
          output_json: z.string().optional(),
          metrics_json: z.string().optional(),
          output_json_preview: z.string().optional(),
          metrics_json_preview: z.string().optional(),
          output_json_bytes: z.number().int().nonnegative().optional(),
          metrics_json_bytes: z.number().int().nonnegative().optional(),
          output_json_truncated: z.boolean().optional(),
          metrics_json_truncated: z.boolean().optional(),
        })
      ),
      workspace: z
        .object({
          status: z.enum(['ready', 'workspace_missing', 'original_dir_missing', 'original_file_missing']),
          workspace_root: z.string().nullable(),
          original_dir: z.string().nullable(),
          reports_dir: z.string().nullable(),
          ghidra_dir: z.string().nullable(),
          workspace_exists: z.boolean(),
          original_dir_exists: z.boolean(),
          reports_dir_exists: z.boolean(),
          ghidra_dir_exists: z.boolean(),
          original_present: z.boolean(),
          original_file_count: z.number().int().nonnegative(),
          original_files: z.array(z.string()),
          original_file_list_truncated: z.boolean(),
          alternate_workspace_root: z.string().nullable(),
          alternate_original_dir: z.string().nullable(),
          alternate_original_present: z.boolean(),
          alternate_original_file_count: z.number().int().nonnegative(),
          alternate_original_files: z.array(z.string()),
          alternate_original_file_list_truncated: z.boolean(),
          remediation: z.array(z.string()),
        })
        .optional(),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
})

export type SampleProfileGetOutput = z.infer<typeof SampleProfileGetOutputSchema>

export const sampleProfileGetToolDefinition: ToolDefinition = {
  name: 'sample.profile.get',
  description:
    'Query sample metadata, analysis history, and workspace integrity. Defaults to a bounded compact view with analysis output previews instead of returning every raw analysis payload inline.',
  inputSchema: SampleProfileGetInputSchema,
  outputSchema: SampleProfileGetOutputSchema,
}

function truncateInlineText(
  value: string | null,
  limit: number
): {
  full: string | undefined
  preview: string | undefined
  bytes: number | undefined
  truncated: boolean | undefined
} {
  if (!value) {
    return {
      full: undefined,
      preview: undefined,
      bytes: undefined,
      truncated: undefined,
    }
  }

  const preview = value.length > limit ? `${value.slice(0, limit)}…` : value
  return {
    full: value,
    preview,
    bytes: Buffer.byteLength(value, 'utf8'),
    truncated: value.length > limit,
  }
}

function limitInlineFiles(files: string[], limit: number): { files: string[]; truncated: boolean } {
  return {
    files: files.slice(0, limit),
    truncated: files.length > limit,
  }
}

export function createSampleProfileGetHandler(
  database: DatabaseManager,
  workspaceManager?: WorkspaceManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = SampleProfileGetInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)

      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      if (typeof input.stale_running_ms === 'number') {
        database.reapStaleAnalyses(input.stale_running_ms, input.sample_id)
      }
      const analyses = database.findAnalysesBySample(input.sample_id)
      const workspace = workspaceManager
        ? await inspectSampleWorkspace(workspaceManager, input.sample_id)
        : undefined
      const boundedAnalyses = analyses.slice(0, input.max_analyses)
      const limitedWorkspace = workspace
        ? (() => {
            const originalFiles = limitInlineFiles(
              workspace.original_files,
              input.workspace_file_preview_limit
            )
            const alternateOriginalFiles = limitInlineFiles(
              workspace.alternate_original_files,
              input.workspace_file_preview_limit
            )

            return {
              ...workspace,
              original_files: originalFiles.files,
              original_file_list_truncated: originalFiles.truncated,
              alternate_original_file_count: workspace.alternate_original_files.length,
              alternate_original_files: alternateOriginalFiles.files,
              alternate_original_file_list_truncated: alternateOriginalFiles.truncated,
            }
          })()
        : undefined

      return {
        ok: true,
        data: {
          sample: {
            id: sample.id,
            sha256: sample.sha256,
            md5: sample.md5,
            size: sample.size,
            file_type: sample.file_type || undefined,
            created_at: sample.created_at,
            source: sample.source,
          },
          analysis_summary: {
            detail: input.analysis_detail,
            total_count: analyses.length,
            returned_count: boundedAnalyses.length,
            analyses_truncated: analyses.length > boundedAnalyses.length,
            json_preview_chars: input.json_preview_chars,
          },
          analyses: boundedAnalyses.map((analysis) => {
            const output = truncateInlineText(analysis.output_json, input.json_preview_chars)
            const metrics = truncateInlineText(analysis.metrics_json, input.json_preview_chars)
            return {
              id: analysis.id,
              stage: analysis.stage,
              backend: analysis.backend,
              status: analysis.status,
              started_at: analysis.started_at || undefined,
              finished_at: analysis.finished_at || undefined,
              output_json: input.analysis_detail === 'full' ? output.full : undefined,
              metrics_json: input.analysis_detail === 'full' ? metrics.full : undefined,
              output_json_preview: input.analysis_detail === 'compact' ? output.preview : undefined,
              metrics_json_preview:
                input.analysis_detail === 'compact' ? metrics.preview : undefined,
              output_json_bytes: output.bytes,
              metrics_json_bytes: metrics.bytes,
              output_json_truncated:
                input.analysis_detail === 'compact' ? output.truncated : undefined,
              metrics_json_truncated:
                input.analysis_detail === 'compact' ? metrics.truncated : undefined,
            }
          }),
          workspace: limitedWorkspace,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
      }
    }
  }
}
