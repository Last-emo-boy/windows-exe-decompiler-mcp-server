/**
 * Shared helpers for interpreting persisted Ghidra analysis states.
 */

import type { Analysis } from './database.js'

export const GHIDRA_READY_STATUSES = new Set(['done', 'partial_success'])
export const GHIDRA_STRICT_READY_STATUSES = new Set(['done'])

export type GhidraCapability = 'function_index' | 'decompile' | 'cfg'
export type GhidraCapabilityState = 'ready' | 'degraded' | 'missing'

export interface GhidraCapabilityStatus {
  available: boolean
  status: GhidraCapabilityState
  reason?: string
  warnings?: string[]
  checked_at?: string
  target?: string
  details?: Record<string, unknown>
}

export interface GhidraAnalysisMetadata {
  function_count?: number
  project_path?: string
  project_key?: string
  ghidra_execution?: {
    project_root?: string
    log_root?: string
    command_log_paths?: string[]
    runtime_log_paths?: string[]
    progress_stages?: Array<{
      progress?: number
      stage?: string
      detail?: string | null
      recorded_at?: string | null
    }>
    java_exception?: {
      exception_class?: string
      message?: string
      stack_preview?: string[]
    }
  }
  ghidra_diagnostics?: {
    log_path?: string
    runtime_log_path?: string
    java_exception?: {
      exception_class?: string
      message?: string
      stack_preview?: string[]
    }
  }
  function_extraction?: {
    status?: string
    script_used?: string
    warnings?: string[]
    attempts?: unknown[]
  }
  readiness?: Partial<Record<GhidraCapability, GhidraCapabilityStatus>>
  end_to_end_probe?: {
    target?: string
    decompile?: GhidraCapabilityStatus
    cfg?: GhidraCapabilityStatus
    checked_at?: string
  }
  [key: string]: unknown
}

export interface GhidraReadinessMatrix {
  function_index: GhidraCapabilityStatus
  decompile: GhidraCapabilityStatus
  cfg: GhidraCapabilityStatus
}

function normalizeCapabilityStatus(
  raw: unknown,
  fallback: GhidraCapabilityStatus
): GhidraCapabilityStatus {
  if (!raw || typeof raw !== 'object') {
    return fallback
  }

  const candidate = raw as Record<string, unknown>
  const statusRaw = String(candidate.status || fallback.status || 'missing').toLowerCase()
  const status: GhidraCapabilityState =
    statusRaw === 'ready'
      ? 'ready'
      : statusRaw === 'degraded'
        ? 'degraded'
        : 'missing'

  return {
    available:
      typeof candidate.available === 'boolean' ? candidate.available : status === 'ready',
    status,
    reason:
      typeof candidate.reason === 'string'
        ? candidate.reason
        : typeof fallback.reason === 'string'
          ? fallback.reason
          : undefined,
    warnings: Array.isArray(candidate.warnings)
      ? candidate.warnings.filter((item): item is string => typeof item === 'string')
      : fallback.warnings,
    checked_at:
      typeof candidate.checked_at === 'string'
        ? candidate.checked_at
        : fallback.checked_at,
    target:
      typeof candidate.target === 'string'
        ? candidate.target
        : fallback.target,
    details:
      candidate.details && typeof candidate.details === 'object'
        ? (candidate.details as Record<string, unknown>)
        : fallback.details,
  }
}

function buildLegacyCapabilityFallback(
  capability: GhidraCapability,
  analysis: Pick<Analysis, 'status' | 'output_json'>,
  metadata: GhidraAnalysisMetadata
): GhidraCapabilityStatus {
  const hasProject = Boolean(metadata.project_path && metadata.project_key)
  const functionCount =
    typeof metadata.function_count === 'number'
      ? metadata.function_count
      : 0
  const extractionStatus = String(metadata.function_extraction?.status || '').toLowerCase()
  const extractionWarnings = Array.isArray(metadata.function_extraction?.warnings)
    ? metadata.function_extraction?.warnings
    : undefined
  const strictReady = isStrictGhidraReadyStatus(analysis.status)
  const looseReady = isGhidraReadyStatus(analysis.status)

  if (capability === 'function_index') {
    if (functionCount > 0) {
      return {
        available: true,
        status: 'ready',
        warnings: extractionWarnings,
      }
    }
    if (looseReady && extractionStatus === 'failed') {
      return {
        available: false,
        status: 'missing',
        reason: 'Function extraction failed after headless analysis completed.',
        warnings: extractionWarnings,
      }
    }
    if (looseReady) {
      return {
        available: false,
        status: 'missing',
        reason: 'Legacy Ghidra record has no extracted function index.',
        warnings: extractionWarnings,
      }
    }
    return {
      available: false,
      status: 'missing',
      reason: 'No completed function-index extraction recorded.',
    }
  }

  if (hasProject && strictReady) {
    return {
      available: true,
      status: 'ready',
      warnings: extractionWarnings,
    }
  }

  if (hasProject && looseReady) {
    return {
      available: false,
      status: 'degraded',
      reason:
        capability === 'decompile'
          ? 'Project metadata exists, but decompile readiness was not validated.'
          : 'Project metadata exists, but CFG readiness was not validated.',
      warnings: extractionWarnings,
    }
  }

  return {
    available: false,
    status: 'missing',
    reason:
      capability === 'decompile'
        ? 'No decompile-capable Ghidra project metadata found.'
        : 'No CFG-capable Ghidra project metadata found.',
    warnings: extractionWarnings,
  }
}

export function parseGhidraAnalysisMetadata(
  outputJson: string | null | undefined
): GhidraAnalysisMetadata {
  if (!outputJson) {
    return {}
  }

  try {
    const parsed = JSON.parse(outputJson) as unknown
    if (!parsed || typeof parsed !== 'object') {
      return {}
    }
    return parsed as GhidraAnalysisMetadata
  } catch {
    return {}
  }
}

export function isGhidraReadyStatus(status: string | null | undefined): boolean {
  if (!status) {
    return false
  }
  return GHIDRA_READY_STATUSES.has(status)
}

export function isStrictGhidraReadyStatus(status: string | null | undefined): boolean {
  if (!status) {
    return false
  }
  return GHIDRA_STRICT_READY_STATUSES.has(status)
}

export function getGhidraReadiness(
  analysis: Pick<Analysis, 'status' | 'output_json'>
): GhidraReadinessMatrix {
  const metadata = parseGhidraAnalysisMetadata(analysis.output_json)
  const readiness = metadata.readiness || {}

  return {
    function_index: normalizeCapabilityStatus(
      readiness.function_index,
      buildLegacyCapabilityFallback('function_index', analysis, metadata)
    ),
    decompile: normalizeCapabilityStatus(
      readiness.decompile,
      buildLegacyCapabilityFallback('decompile', analysis, metadata)
    ),
    cfg: normalizeCapabilityStatus(
      readiness.cfg,
      buildLegacyCapabilityFallback('cfg', analysis, metadata)
    ),
  }
}

export function getGhidraCapabilityStatus(
  analysis: Pick<Analysis, 'status' | 'output_json'>,
  capability: GhidraCapability
): GhidraCapabilityStatus {
  return getGhidraReadiness(analysis)[capability]
}

export function isGhidraCapabilityReady(
  analysis: Pick<Analysis, 'status' | 'output_json'>,
  capability: GhidraCapability
): boolean {
  const state = getGhidraCapabilityStatus(analysis, capability)
  return state.available === true && state.status === 'ready'
}

function analysisSortKey(analysis: Analysis): number {
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

export function findBestGhidraAnalysis(
  analyses: Analysis[],
  capability?: GhidraCapability
): Analysis | undefined {
  const sorted = [...analyses]
    .filter((analysis) => analysis.backend === 'ghidra')
    .sort((left, right) => analysisSortKey(right) - analysisSortKey(left))

  if (!capability) {
    return sorted[0]
  }

  const ready = sorted.find((analysis) => isGhidraCapabilityReady(analysis, capability))
  if (ready) {
    return ready
  }

  return sorted.find((analysis) => {
    const status = getGhidraCapabilityStatus(analysis, capability)
    return status.status === 'degraded'
  })
}
