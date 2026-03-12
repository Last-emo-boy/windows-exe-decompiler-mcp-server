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

export const SampleProfileGetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe('Optional stale-analysis reap threshold in milliseconds. Omit or null to disable auto-reaping.'),
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
          alternate_workspace_root: z.string().nullable(),
          alternate_original_dir: z.string().nullable(),
          alternate_original_present: z.boolean(),
          alternate_original_files: z.array(z.string()),
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
    'Query sample metadata, completed analyses, and workspace integrity including whether workspace/original still contains the original sample file.',
  inputSchema: SampleProfileGetInputSchema,
  outputSchema: SampleProfileGetOutputSchema,
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
          analyses: analyses.map((analysis) => ({
            id: analysis.id,
            stage: analysis.stage,
            backend: analysis.backend,
            status: analysis.status,
            started_at: analysis.started_at || undefined,
            finished_at: analysis.finished_at || undefined,
            output_json: analysis.output_json || undefined,
            metrics_json: analysis.metrics_json || undefined,
          })),
          workspace,
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
