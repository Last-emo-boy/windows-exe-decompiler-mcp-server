/**
 * artifacts.list tool implementation
 * Enumerates artifact inventory for a sample with on-disk observability metadata.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { listArtifactInventory, normalizeRelativeArtifactPath } from '../artifact-inventory.js'

const TOOL_NAME = 'artifacts.list'
const TOOL_VERSION = '0.1.2'

export const ArtifactsListInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  artifact_type: z.string().optional().describe('Optional artifact type filter'),
  artifact_types: z
    .array(z.string())
    .optional()
    .describe('Optional artifact type filter list (union with artifact_type)'),
  include_missing: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include DB artifact records whose files are missing on disk'),
  page: z.number().int().min(1).optional().default(1),
  page_size: z.number().int().min(1).max(500).optional().default(100),
  sort_by: z.enum(['created_at', 'type', 'path', 'size_bytes']).optional().default('created_at'),
  sort_order: z.enum(['asc', 'desc']).optional().default('desc'),
  path_prefix: z
    .string()
    .optional()
    .describe('Optional relative path prefix filter, useful for narrowing to one export/session directory'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional derived session tag filter such as reports/reconstruct/<session>'),
  retention_bucket: z
    .enum(['active', 'recent', 'archive'])
    .optional()
    .describe('Optional lifecycle filter based on artifact age'),
  latest_only: z
    .boolean()
    .optional()
    .default(false)
    .describe('Keep only the latest artifact for each artifact type after filtering'),
  high_value_only: z
    .boolean()
    .optional()
    .default(false)
    .describe('Show only high-value artifact categories (manifest/report/gaps/trace/export)'),
  include_untracked_files: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include files under workspace export roots even if not registered in artifacts table'),
  recursive: z
    .boolean()
    .optional()
    .default(true)
    .describe('Recursively scan export roots for untracked files'),
  scan_roots: z
    .array(z.string())
    .optional()
    .default(['reports', 'ghidra', 'dotnet'])
    .describe('Workspace subdirectories to scan for untracked export files'),
})

export type ArtifactsListInput = z.infer<typeof ArtifactsListInputSchema>

const ArtifactItemSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().nullable(),
  created_at: z.string(),
  exists: z.boolean(),
  size_bytes: z.number().nullable(),
  modified_at: z.string().nullable(),
  tracked: z.boolean(),
  session_tag: z.string().nullable(),
  retention_bucket: z.enum(['active', 'recent', 'archive']),
  age_days: z.number().int().nonnegative(),
})

const ArtifactsListSummarySchema = z.object({
  total_count: z.number().int().nonnegative(),
  filtered_count: z.number().int().nonnegative(),
  missing_count: z.number().int().nonnegative(),
  untracked_count: z.number().int().nonnegative(),
  by_type: z.record(z.number()),
  latest_by_type: z.record(
    z.object({
      id: z.string(),
      path: z.string(),
      created_at: z.string(),
      tracked: z.boolean(),
    })
  ),
  latest_by_session: z.record(
    z.object({
      id: z.string(),
      path: z.string(),
      created_at: z.string(),
      type: z.string(),
      tracked: z.boolean(),
    })
  ),
  session_index: z.record(
    z.object({
      count: z.number().int().nonnegative(),
      latest_created_at: z.string(),
      tracked_count: z.number().int().nonnegative(),
      untracked_count: z.number().int().nonnegative(),
      types: z.array(z.string()),
      retention_buckets: z.array(z.string()),
    })
  ),
  by_retention_bucket: z.record(z.number()),
  high_value_types: z.array(z.string()),
})

export const ArtifactsListOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      artifact_type: z.string().nullable(),
      artifact_types: z.array(z.string()).nullable(),
      path_prefix: z.string().nullable(),
      session_tag: z.string().nullable(),
      retention_bucket: z.enum(['active', 'recent', 'archive']).nullable(),
      latest_only: z.boolean(),
      tool_version: z.string(),
      count: z.number().int().nonnegative(),
      total_count: z.number().int().nonnegative(),
      page: z.number().int().positive(),
      page_size: z.number().int().positive(),
      total_pages: z.number().int().nonnegative(),
      artifacts: z.array(ArtifactItemSchema),
      summary: ArtifactsListSummarySchema,
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const artifactsListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'List artifact records for a sample with existence/size timestamps, type filtering, and paginated high-value discovery.',
  inputSchema: ArtifactsListInputSchema,
  outputSchema: ArtifactsListOutputSchema,
}

function artifactValueScore(type: string, artifactPath: string): number {
  const valueSignals = [
    'manifest',
    'gaps',
    'report',
    'summary',
    'triage',
    'reconstruct',
    'trace',
    'ioc_export',
    'attack',
    'sandbox',
  ]
  const normalized = `${type} ${artifactPath}`.toLowerCase()
  let score = 0
  for (const signal of valueSignals) {
    if (normalized.includes(signal)) {
      score += 1
    }
  }
  return score
}

function compareValues(a: string | number | null, b: string | number | null): number {
  if (a === null && b === null) {
    return 0
  }
  if (a === null) {
    return -1
  }
  if (b === null) {
    return 1
  }
  if (typeof a === 'number' && typeof b === 'number') {
    return a - b
  }
  return String(a).localeCompare(String(b))
}

function toTimestamp(value: string | null): number {
  if (!value) {
    return 0
  }
  const parsed = new Date(value).getTime()
  return Number.isFinite(parsed) ? parsed : 0
}

export function createArtifactsListHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = ArtifactsListInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const typeFilter = new Set<string>()
      if (input.artifact_type) {
        typeFilter.add(input.artifact_type)
      }
      for (const item of input.artifact_types || []) {
        typeFilter.add(item)
      }

      const merged = await listArtifactInventory(workspaceManager, database, input.sample_id, {
        artifactTypes: typeFilter,
        includeMissing: input.include_missing,
        includeUntrackedFiles: input.include_untracked_files,
        recursive: input.recursive,
        scanRoots: input.scan_roots,
      })

      let filtered = merged
      if (input.path_prefix) {
        const normalizedPrefix = normalizeRelativeArtifactPath(input.path_prefix).toLowerCase()
        filtered = filtered.filter((item) =>
          normalizeRelativeArtifactPath(item.path).toLowerCase().startsWith(normalizedPrefix)
        )
      }
      if (input.session_tag) {
        filtered = filtered.filter((item) => item.session_tag === input.session_tag)
      }
      if (input.retention_bucket) {
        filtered = filtered.filter((item) => item.retention_bucket === input.retention_bucket)
      }
      if (input.high_value_only) {
        filtered = filtered.filter((item) => artifactValueScore(item.type, item.path) > 0)
      }

      if (input.latest_only) {
        const latestByType = new Map<string, (typeof filtered)[number]>()
        for (const item of filtered) {
          const existing = latestByType.get(item.type)
          if (!existing || toTimestamp(item.created_at) > toTimestamp(existing.created_at)) {
            latestByType.set(item.type, item)
          }
        }
        filtered = Array.from(latestByType.values())
      }

      filtered.sort((left, right) => {
        const direction = input.sort_order === 'asc' ? 1 : -1
        if (input.sort_by === 'size_bytes') {
          return direction * compareValues(left.size_bytes, right.size_bytes)
        }
        if (input.sort_by === 'type') {
          return direction * compareValues(left.type, right.type)
        }
        if (input.sort_by === 'path') {
          return direction * compareValues(left.path, right.path)
        }
        return direction * compareValues(left.created_at, right.created_at)
      })

      const totalCount = filtered.length
      const pageSize = input.page_size
      const totalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / pageSize)
      const boundedPage =
        totalPages === 0 ? 1 : Math.min(Math.max(input.page, 1), Math.max(totalPages, 1))
      const startIndex = (boundedPage - 1) * pageSize
      const pagedArtifacts = filtered.slice(startIndex, startIndex + pageSize)

      const missingCount = merged.filter((item) => item.tracked && !item.exists).length
      const untrackedCount = merged.filter((item) => !item.tracked).length
      const byType: Record<string, number> = {}
      const latestByType: Record<
        string,
        { id: string; path: string; created_at: string; tracked: boolean }
      > = {}
      const latestBySession: Record<
        string,
        { id: string; path: string; created_at: string; type: string; tracked: boolean }
      > = {}
      const sessionIndex: Record<
        string,
        {
          count: number
          latest_created_at: string
          tracked_count: number
          untracked_count: number
          types: Set<string>
          retention_buckets: Set<string>
        }
      > = {}
      const byRetentionBucket: Record<string, number> = {}
      const highValueTypes = new Set<string>()
      for (const item of filtered) {
        byType[item.type] = (byType[item.type] || 0) + 1
        byRetentionBucket[item.retention_bucket] = (byRetentionBucket[item.retention_bucket] || 0) + 1
        const existing = latestByType[item.type]
        if (!existing || toTimestamp(item.created_at) > toTimestamp(existing.created_at)) {
          latestByType[item.type] = {
            id: item.id,
            path: item.path,
            created_at: item.created_at,
            tracked: item.tracked,
          }
        }
        if (item.session_tag) {
          const existingSession = latestBySession[item.session_tag]
          if (!existingSession || toTimestamp(item.created_at) > toTimestamp(existingSession.created_at)) {
            latestBySession[item.session_tag] = {
              id: item.id,
              path: item.path,
              created_at: item.created_at,
              type: item.type,
              tracked: item.tracked,
            }
          }
          const currentSession = sessionIndex[item.session_tag] || {
            count: 0,
            latest_created_at: item.created_at,
            tracked_count: 0,
            untracked_count: 0,
            types: new Set<string>(),
            retention_buckets: new Set<string>(),
          }
          currentSession.count += 1
          currentSession.latest_created_at =
            toTimestamp(item.created_at) > toTimestamp(currentSession.latest_created_at)
              ? item.created_at
              : currentSession.latest_created_at
          currentSession.tracked_count += item.tracked ? 1 : 0
          currentSession.untracked_count += item.tracked ? 0 : 1
          currentSession.types.add(item.type)
          currentSession.retention_buckets.add(item.retention_bucket)
          sessionIndex[item.session_tag] = currentSession
        }
        if (artifactValueScore(item.type, item.path) > 0) {
          highValueTypes.add(item.type)
        }
      }

      const warnings =
        missingCount > 0 || untrackedCount > 0
          ? [
              ...(missingCount > 0
                ? [
                    `${missingCount} artifact record(s) are missing on disk${
                      input.include_missing
                        ? '; keeping them in output for audit visibility.'
                        : '; hidden because include_missing=false.'
                    }`,
                  ]
                : []),
              ...(untrackedCount > 0
                ? [
                    `Discovered ${untrackedCount} untracked file artifact(s) under scan roots: ${input.scan_roots.join(
                      ', '
                    )}.`,
                  ]
                : []),
            ]
          : undefined

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          artifact_type: input.artifact_type || null,
          artifact_types: typeFilter.size > 0 ? Array.from(typeFilter) : null,
          path_prefix: input.path_prefix || null,
          session_tag: input.session_tag || null,
          retention_bucket: input.retention_bucket || null,
          latest_only: input.latest_only,
          tool_version: TOOL_VERSION,
          count: pagedArtifacts.length,
          total_count: totalCount,
          page: boundedPage,
          page_size: pageSize,
          total_pages: totalPages,
          artifacts: pagedArtifacts,
          summary: {
            total_count: merged.length,
            filtered_count: totalCount,
            missing_count: missingCount,
            untracked_count: untrackedCount,
            by_type: byType,
            latest_by_type: latestByType,
            latest_by_session: latestBySession,
            session_index: Object.fromEntries(
              Object.entries(sessionIndex).map(([sessionTag, item]) => [
                sessionTag,
                {
                  count: item.count,
                  latest_created_at: item.latest_created_at,
                  tracked_count: item.tracked_count,
                  untracked_count: item.untracked_count,
                  types: Array.from(item.types).sort(),
                  retention_buckets: Array.from(item.retention_buckets).sort(),
                },
              ])
            ),
            by_retention_bucket: byRetentionBucket,
            high_value_types: Array.from(highValueTypes).sort(),
          },
        },
        warnings,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
