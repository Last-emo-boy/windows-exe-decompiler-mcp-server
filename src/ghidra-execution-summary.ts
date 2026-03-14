import { z } from 'zod'
import type { Analysis } from './database.js'
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from './ghidra-analysis-status.js'
import {
  getConfiguredGhidraLogRoot,
  getConfiguredGhidraProjectRoot,
} from './ghidra-config.js'

export const GhidraProgressStageSchema = z.object({
  progress: z.number().int().min(0).max(100),
  stage: z.string(),
  detail: z.string().nullable(),
  recorded_at: z.string().nullable(),
})

export const GhidraJavaExceptionSchema = z.object({
  exception_class: z.string(),
  message: z.string(),
  stack_head: z.string().nullable(),
})

export const GhidraExecutionSummarySchema = z.object({
  analysis_id: z.string(),
  selected_source: z.enum(['best_ready', 'latest_attempt']),
  backend: z.string(),
  status: z.string(),
  function_count: z.number().int().nonnegative(),
  finished_at: z.string().nullable(),
  project_path: z.string().nullable(),
  project_key: z.string().nullable(),
  project_root: z.string().nullable(),
  log_root: z.string().nullable(),
  function_extraction_status: z.string().nullable(),
  function_extraction_script: z.string().nullable(),
  command_log_paths: z.array(z.string()),
  runtime_log_paths: z.array(z.string()),
  progress_stages: z.array(GhidraProgressStageSchema),
  readiness_status: z
    .object({
      function_index: z.enum(['ready', 'degraded', 'missing']),
      decompile: z.enum(['ready', 'degraded', 'missing']),
      cfg: z.enum(['ready', 'degraded', 'missing']),
    })
    .optional(),
  java_exception: GhidraJavaExceptionSchema.nullable(),
  warnings: z.array(z.string()),
})

type GhidraExecutionSummary = z.infer<typeof GhidraExecutionSummarySchema>

function parseStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return []
  }
  return raw.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
}

function parseProgressStages(raw: unknown): GhidraExecutionSummary['progress_stages'] {
  if (!Array.isArray(raw)) {
    return []
  }

  return raw
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
    .map((item) => {
      const progress = typeof item.progress === 'number' ? item.progress : 0
      return {
        progress: Math.max(0, Math.min(100, Math.round(progress))),
        stage: typeof item.stage === 'string' ? item.stage : 'unknown',
        detail: typeof item.detail === 'string' ? item.detail : null,
        recorded_at: typeof item.recorded_at === 'string' ? item.recorded_at : null,
      }
    })
}

function parseJavaException(raw: unknown): GhidraExecutionSummary['java_exception'] {
  if (!raw || typeof raw !== 'object') {
    return null
  }
  const candidate = raw as Record<string, unknown>
  if (typeof candidate.exception_class !== 'string' || typeof candidate.message !== 'string') {
    return null
  }
  return {
    exception_class: candidate.exception_class,
    message: candidate.message,
    stack_head:
      typeof candidate.stack_head === 'string'
        ? candidate.stack_head
        : Array.isArray(candidate.stack_preview) && typeof candidate.stack_preview[0] === 'string'
          ? candidate.stack_preview[0]
          : null,
  }
}

function latestAnalysisTimestamp(analysis: Analysis): number {
  const candidates = [analysis.finished_at, analysis.started_at]
  for (const candidate of candidates) {
    if (!candidate) {
      continue
    }
    const ts = new Date(candidate).getTime()
    if (Number.isFinite(ts)) {
      return ts
    }
  }
  return 0
}

function dedupe(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    )
  )
}

export function buildGhidraExecutionSummary(
  analyses: Analysis[]
): GhidraExecutionSummary | null {
  const ghidraAnalyses = analyses.filter(
    (analysis) => analysis.backend === 'ghidra' || analysis.stage === 'ghidra'
  )
  if (ghidraAnalyses.length === 0) {
    return null
  }

  const readyAnalysis = findBestGhidraAnalysis(ghidraAnalyses, 'function_index')
  const latestAnalysis = [...ghidraAnalyses].sort(
    (left, right) => latestAnalysisTimestamp(right) - latestAnalysisTimestamp(left)
  )[0]
  const selected = readyAnalysis || latestAnalysis
  if (!selected) {
    return null
  }

  const metadata = parseGhidraAnalysisMetadata(selected.output_json)
  const execution =
    metadata.ghidra_execution && typeof metadata.ghidra_execution === 'object'
      ? (metadata.ghidra_execution as Record<string, unknown>)
      : null
  const diagnostics =
    metadata.ghidra_diagnostics && typeof metadata.ghidra_diagnostics === 'object'
      ? (metadata.ghidra_diagnostics as Record<string, unknown>)
      : null
  const readiness = getGhidraReadiness(selected)
  const functionExtraction =
    metadata.function_extraction && typeof metadata.function_extraction === 'object'
      ? (metadata.function_extraction as Record<string, unknown>)
      : null
  const commandLogPaths = dedupe([
    ...(execution ? parseStringArray(execution.command_log_paths) : []),
    diagnostics && typeof diagnostics.log_path === 'string' ? diagnostics.log_path : undefined,
  ])
  const runtimeLogPaths = dedupe([
    ...(execution ? parseStringArray(execution.runtime_log_paths) : []),
    diagnostics && typeof diagnostics.runtime_log_path === 'string'
      ? diagnostics.runtime_log_path
      : undefined,
  ])

  const warnings = dedupe([
    ...(Array.isArray(functionExtraction?.warnings)
      ? functionExtraction!.warnings.filter((item): item is string => typeof item === 'string')
      : []),
    ...((readiness.function_index.warnings || []) as string[]),
    ...((readiness.decompile.warnings || []) as string[]),
    ...((readiness.cfg.warnings || []) as string[]),
  ])

  return {
    analysis_id: selected.id,
    selected_source: readyAnalysis && readyAnalysis.id === selected.id ? 'best_ready' : 'latest_attempt',
    backend: selected.backend,
    status: selected.status,
    function_count: typeof metadata.function_count === 'number' ? metadata.function_count : 0,
    finished_at: selected.finished_at || selected.started_at || null,
    project_path:
      typeof metadata.project_path === 'string' ? metadata.project_path : null,
    project_key: typeof metadata.project_key === 'string' ? metadata.project_key : null,
    project_root:
      execution && typeof execution.project_root === 'string'
        ? execution.project_root
        : getConfiguredGhidraProjectRoot(),
    log_root:
      execution && typeof execution.log_root === 'string'
        ? execution.log_root
        : getConfiguredGhidraLogRoot(),
    function_extraction_status:
      functionExtraction && typeof functionExtraction.status === 'string'
        ? functionExtraction.status
        : null,
    function_extraction_script:
      functionExtraction && typeof functionExtraction.script_used === 'string'
        ? functionExtraction.script_used
        : null,
    command_log_paths: commandLogPaths,
    runtime_log_paths: runtimeLogPaths,
    progress_stages: parseProgressStages(execution?.progress_stages),
    readiness_status: {
      function_index: readiness.function_index.status,
      decompile: readiness.decompile.status,
      cfg: readiness.cfg.status,
    },
    java_exception:
      parseJavaException(execution?.java_exception) ||
      parseJavaException(diagnostics?.java_exception),
    warnings,
  }
}
