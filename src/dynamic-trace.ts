import fs from 'fs/promises'
import path from 'path'
import type { DatabaseManager } from './database.js'
import type { WorkspaceManager } from './workspace-manager.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'

export type DynamicTraceSourceFormat =
  | 'normalized'
  | 'generic_json'
  | 'frida_json'
  | 'speakeasy_json'
  | 'minidump'
  | 'process_memory'
  | 'raw_dump'
  | 'sandbox_trace'

export type DynamicEvidenceKind = 'trace' | 'memory_snapshot' | 'hybrid'
export type DynamicEvidenceLayerName =
  | 'safe_simulation'
  | 'memory_or_hybrid'
  | 'executed_trace'
export type DynamicEvidenceScope = 'all' | 'latest' | 'session'

export interface LoadDynamicTraceEvidenceOptions {
  evidenceScope?: DynamicEvidenceScope
  sessionTag?: string
}

export interface NormalizedDynamicTraceApi {
  api: string
  module?: string
  category: string
  count: number
  confidence: number
  sources: string[]
}

export interface NormalizedDynamicTraceMemoryRegion {
  region_type: string
  purpose: string
  source: string
  confidence: number
  base_address?: string
  size?: number
  protection?: string
  module_name?: string
  segment_name?: string
  indicators: string[]
}

export interface NormalizedDynamicTrace {
  schema_version: '0.1.0'
  source_format: DynamicTraceSourceFormat
  evidence_kind: DynamicEvidenceKind
  source_name?: string
  source_mode?: string
  imported_at: string
  executed: boolean
  raw_event_count: number
  api_calls: NormalizedDynamicTraceApi[]
  memory_regions: NormalizedDynamicTraceMemoryRegion[]
  modules: string[]
  strings: string[]
  stages: string[]
  risk_hints: string[]
  notes: string[]
}

export interface DynamicEvidenceLayerSummary {
  layer: DynamicEvidenceLayerName
  artifact_count: number
  confidence_band: 'baseline' | 'suggestive' | 'high'
  source_formats: string[]
  evidence_kinds: string[]
  source_names: string[]
  source_modes: string[]
  latest_imported_at: string | null
  summary: string
}

export interface DynamicTraceSummary {
  artifact_count: number
  artifact_ids?: string[]
  executed: boolean
  executed_artifact_count?: number
  api_count: number
  memory_region_count: number
  stage_count: number
  observed_apis: string[]
  high_signal_apis: string[]
  memory_regions: string[]
  region_types?: string[]
  protections?: string[]
  address_ranges?: string[]
  region_owners?: string[]
  observed_modules?: string[]
  segment_names?: string[]
  observed_strings?: string[]
  stages: string[]
  risk_hints: string[]
  source_formats?: string[]
  evidence_kinds?: string[]
  source_names?: string[]
  source_modes?: string[]
  confidence_layers?: DynamicEvidenceLayerSummary[]
  earliest_imported_at?: string | null
  latest_imported_at?: string | null
  scope_note?: string
  evidence_scope?: DynamicEvidenceScope
  session_selector?: string | null
  session_tags?: string[]
  evidence: string[]
  summary: string
}

interface LoadedDynamicTraceArtifact {
  artifact: {
    id: string
    type: string
    path: string
    created_at: string
  }
  normalized: NormalizedDynamicTrace
  session_tags: string[]
}

const LATEST_DYNAMIC_EVIDENCE_WINDOW_MS = 10 * 1000

const HIGH_SIGNAL_APIS = new Set([
  'OpenProcess',
  'OpenProcessToken',
  'CreateProcessW',
  'CreateProcessA',
  'WriteProcessMemory',
  'ReadProcessMemory',
  'VirtualAllocEx',
  'VirtualProtectEx',
  'CreateRemoteThread',
  'ResumeThread',
  'SetThreadContext',
  'NtQueryInformationProcess',
  'NtQuerySystemInformation',
  'GetProcAddress',
  'LoadLibraryA',
  'LoadLibraryW',
  'LoadLibraryExA',
  'LoadLibraryExW',
])

const DYNAMIC_RESOLUTION_APIS = new Set([
  'GetProcAddress',
  'LoadLibrary',
  'LoadLibraryA',
  'LoadLibraryW',
  'LoadLibraryExA',
  'LoadLibraryExW',
])

function dedupeStrings(values: string[], limit?: number): string[] {
  const unique = Array.from(
    new Set(values.map((item) => item.trim()).filter((item) => item.length > 0))
  )
  return typeof limit === 'number' ? unique.slice(0, limit) : unique
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === 'string')
}

function normalizeApiName(value: string): string {
  const trimmed = value.trim()
  return trimmed.replace(/\(.*/, '').replace(/^.*!/, '')
}

function asObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function readFirstString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim()
    }
  }
  return undefined
}

function readFirstNumber(obj: Record<string, unknown>, keys: string[]): number | undefined {
  for (const key of keys) {
    const value = obj[key]
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value
    }
    if (typeof value === 'string' && value.trim().length > 0) {
      const parsed = Number(value)
      if (Number.isFinite(parsed)) {
        return parsed
      }
    }
  }
  return undefined
}

function normalizeAddress(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return `0x${Math.trunc(value).toString(16)}`
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim()
  }
  return undefined
}

function categorizeApi(api: string): string {
  const normalized = normalizeApiName(api)
  if (DYNAMIC_RESOLUTION_APIS.has(normalized)) {
    return 'dynamic_resolution'
  }
  if (/Process|Thread|RemoteThread|VirtualAllocEx|VirtualProtectEx|SetThreadContext|ResumeThread/i.test(normalized)) {
    return 'process_manipulation'
  }
  if (/Reg(Open|Set|Query|Create|Delete)/i.test(normalized)) {
    return 'registry'
  }
  if (/CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|FindFirstFile|FindNextFile/i.test(normalized)) {
    return 'filesystem'
  }
  if (/Http|WinInet|Internet|WSA|connect|send|recv|socket/i.test(normalized)) {
    return 'network'
  }
  return 'runtime_api'
}

function deriveStages(apis: string[], memoryRegions: string[]): string[] {
  const stages: string[] = []
  const apiSet = new Set(apis.map((item) => normalizeApiName(item)))
  const regionSet = new Set(memoryRegions.map((item) => item.toLowerCase()))

  if (Array.from(apiSet).some((item) => DYNAMIC_RESOLUTION_APIS.has(item))) {
    stages.push('resolve_dynamic_apis')
  }
  if (
    Array.from(apiSet).some((item) =>
      [
        'OpenProcess',
        'OpenProcessToken',
        'WriteProcessMemory',
        'ReadProcessMemory',
        'VirtualAllocEx',
        'SetThreadContext',
        'ResumeThread',
        'CreateRemoteThread',
      ].includes(item)
    )
  ) {
    stages.push('prepare_remote_process_access')
  }
  if (Array.from(apiSet).some((item) => /CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile/i.test(item))) {
    stages.push('file_operations')
  }
  if (Array.from(apiSet).some((item) => /Reg(Open|Set|Query|Create|Delete)/i.test(item))) {
    stages.push('registry_operations')
  }
  if (Array.from(apiSet).some((item) => /NtQueryInformationProcess|NtQuerySystemInformation/i.test(item))) {
    stages.push('anti_analysis_checks')
  }
  if (
    Array.from(regionSet).some((item) => item.includes('resolution')) ||
    Array.from(regionSet).some((item) => item.includes('dispatch'))
  ) {
    stages.push('dispatch_table_assembly')
  }

  return dedupeStrings(stages)
}

function deriveRiskHints(apis: string[], evidenceKind: DynamicEvidenceKind): string[] {
  const hints: string[] = []
  const apiSet = new Set(apis.map((item) => normalizeApiName(item)))

  if (Array.from(apiSet).some((item) => DYNAMIC_RESOLUTION_APIS.has(item))) {
    hints.push('Dynamic API resolution was observed in runtime evidence.')
  }
  if (
    Array.from(apiSet).some((item) =>
      ['WriteProcessMemory', 'ReadProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread'].includes(
        item
      )
    )
  ) {
    hints.push('Process-memory manipulation APIs were observed in runtime evidence.')
  }
  if (
    Array.from(apiSet).some((item) =>
      ['NtQueryInformationProcess', 'NtQuerySystemInformation'].includes(item)
    )
  ) {
    hints.push('Anti-analysis or environment-query APIs were observed in runtime evidence.')
  }
  if (evidenceKind === 'memory_snapshot') {
    hints.push('Evidence is memory-snapshot based; execution was not directly proven by this artifact alone.')
  }

  return hints
}

function classifyDynamicEvidenceLayer(trace: NormalizedDynamicTrace): DynamicEvidenceLayerName {
  if (trace.executed) {
    return 'executed_trace'
  }
  if ((trace.source_mode || '').toLowerCase() === 'safe_simulation') {
    return 'safe_simulation'
  }
  return 'memory_or_hybrid'
}

function confidenceBandForLayer(layer: DynamicEvidenceLayerName): 'baseline' | 'suggestive' | 'high' {
  if (layer === 'executed_trace') {
    return 'high'
  }
  if (layer === 'safe_simulation') {
    return 'suggestive'
  }
  return 'baseline'
}

function summarizeDynamicEvidenceLayer(
  layer: DynamicEvidenceLayerName,
  artifactCount: number,
  sourceModes: string[]
): string {
  if (layer === 'executed_trace') {
    return `Executed trace evidence from ${artifactCount} artifact(s).`
  }
  if (layer === 'safe_simulation') {
    return `Safe simulation evidence from ${artifactCount} artifact(s).`
  }
  if (sourceModes.some((item) => item.toLowerCase() === 'memory_guided')) {
    return `Memory-guided or hybrid runtime evidence from ${artifactCount} artifact(s).`
  }
  return `Memory or hybrid runtime evidence from ${artifactCount} artifact(s).`
}

function collectCandidateEvents(record: Record<string, unknown>): unknown[] {
  const arrays = [
    record.events,
    record.api_calls,
    record.calls,
    record.trace,
    record.entries,
    record.apis,
  ]
  return arrays.flatMap((value) => (Array.isArray(value) ? value : []))
}

function collectCandidateRegions(record: Record<string, unknown>): unknown[] {
  const arrays = [
    record.memory_regions,
    record.regions,
    record.memory_map,
    record.memory_maps,
    record.segments,
  ]
  return arrays.flatMap((value) => (Array.isArray(value) ? value : []))
}

function normalizeRegion(entry: unknown): NormalizedDynamicTraceMemoryRegion | null {
  const obj = asObject(entry)
  if (!obj) {
    return null
  }

  const indicators = dedupeStrings([
    ...toStringArray(obj.indicators),
    ...toStringArray(obj.apis),
    ...toStringArray(obj.strings),
  ])

  return {
    region_type: readFirstString(obj, ['region_type', 'type', 'kind']) || 'memory_region',
    purpose: readFirstString(obj, ['purpose', 'label', 'description']) || 'runtime evidence region',
    source: readFirstString(obj, ['source', 'provider']) || 'imported_trace',
    confidence: readFirstNumber(obj, ['confidence']) || 0.72,
    base_address: normalizeAddress(obj.base_address ?? obj.base ?? obj.start),
    size: readFirstNumber(obj, ['size']),
    protection: readFirstString(obj, ['protection', 'protect']),
    module_name: readFirstString(obj, ['module_name', 'module', 'image']),
    segment_name: readFirstString(obj, ['segment_name', 'section', 'segment']),
    indicators,
  }
}

function aggregateApiEvents(events: unknown[]): NormalizedDynamicTraceApi[] {
  const aggregates = new Map<string, NormalizedDynamicTraceApi>()

  for (const event of events) {
    const obj = asObject(event)
    if (!obj) {
      continue
    }

    const rawApi =
      readFirstString(obj, ['api', 'function', 'name', 'symbol', 'target', 'method']) || ''
    if (!rawApi) {
      continue
    }

    const api = normalizeApiName(rawApi)
    if (!api) {
      continue
    }

    const moduleName = readFirstString(obj, ['module', 'dll', 'library', 'image'])
    const key = `${moduleName || ''}!${api}`
    const existing = aggregates.get(key)
    const confidence = readFirstNumber(obj, ['confidence']) || 0.84
    const count = Math.max(1, Math.trunc(readFirstNumber(obj, ['count', 'hits']) || 1))
    const sources = dedupeStrings([
      ...(existing?.sources || []),
      ...toStringArray(obj.sources),
      ...toStringArray(obj.indicators),
      ...toStringArray(obj.arguments),
      readFirstString(obj, ['source', 'provider']) || '',
    ])

    aggregates.set(key, {
      api,
      module: moduleName,
      category: categorizeApi(api),
      count: (existing?.count || 0) + count,
      confidence: Math.max(existing?.confidence || 0, confidence),
      sources,
    })
  }

  return Array.from(aggregates.values()).sort((left, right) => {
    if (right.count !== left.count) {
      return right.count - left.count
    }
    return right.confidence - left.confidence
  })
}

export function normalizeDynamicTrace(
  raw: unknown,
  options?: {
    sourceFormat?: DynamicTraceSourceFormat
    evidenceKind?: DynamicEvidenceKind
    sourceName?: string
  }
): NormalizedDynamicTrace {
  const record = asObject(raw) || {}
  const sourceFormat = options?.sourceFormat || 'generic_json'
  const evidenceKind = options?.evidenceKind || 'trace'
  const candidateEvents = collectCandidateEvents(record)
  const candidateRegions = collectCandidateRegions(record)
  const apiCalls = aggregateApiEvents(candidateEvents)
  const memoryRegions = candidateRegions
    .map((entry) => normalizeRegion(entry))
    .filter((item): item is NormalizedDynamicTraceMemoryRegion => Boolean(item))
  const modules = dedupeStrings([
    ...toStringArray(record.modules),
    ...apiCalls.map((item) => item.module || ''),
    ...memoryRegions.map((item) => item.module_name || ''),
  ])
  const strings = dedupeStrings([
    ...toStringArray(record.strings),
    ...toStringArray(record.observed_strings),
    ...memoryRegions.flatMap((item) => item.indicators),
  ], 100)
  const stages = dedupeStrings([
    ...toStringArray(record.stages),
    ...deriveStages(
      apiCalls.map((item) => item.api),
      memoryRegions.map((item) => `${item.region_type}:${item.purpose}`)
    ),
  ])
  const executed =
    typeof record.executed === 'boolean' ? record.executed : evidenceKind !== 'memory_snapshot'
  const riskHints = dedupeStrings([
    ...toStringArray(record.risk_hints),
    ...deriveRiskHints(
      apiCalls.map((item) => item.api),
      evidenceKind
    ),
  ])
  const notes = dedupeStrings([
    readFirstString(record, ['summary', 'description']) || '',
    ...toStringArray(record.notes),
  ])

  return {
    schema_version: '0.1.0',
    source_format: sourceFormat,
    evidence_kind: evidenceKind,
    source_name: options?.sourceName,
    source_mode: undefined,
    imported_at: new Date().toISOString(),
    executed,
    raw_event_count: candidateEvents.length,
    api_calls: apiCalls,
    memory_regions: memoryRegions,
    modules,
    strings,
    stages,
    risk_hints: riskHints,
    notes,
  }
}

export function normalizeDynamicTraceArtifactPayload(raw: unknown): NormalizedDynamicTrace | null {
  const record = asObject(raw)
  if (!record) {
    return null
  }

  if (
    record.schema_version === '0.1.0' &&
    typeof record.source_format === 'string' &&
    Array.isArray(record.api_calls)
  ) {
    return raw as NormalizedDynamicTrace
  }

  if (typeof record.run_id === 'string' && (Array.isArray(record.timeline) || Array.isArray(record.api_resolution))) {
    const apiResolution = Array.isArray(record.api_resolution) ? record.api_resolution : []
    const memoryRegions = Array.isArray(record.memory_regions) ? record.memory_regions : []
    const executionHypotheses = Array.isArray(record.execution_hypotheses)
      ? record.execution_hypotheses
      : []
    const timeline = Array.isArray(record.timeline) ? record.timeline : []
    const environment = asObject(record.environment) || {}
    const mode = typeof record.mode === 'string' ? record.mode : 'sandbox'
    const evidenceKind: DynamicEvidenceKind =
      mode === 'memory_guided'
        ? 'hybrid'
        : typeof environment.executed === 'boolean' && environment.executed
          ? 'trace'
          : 'hybrid'

    return {
      schema_version: '0.1.0',
      source_format: 'sandbox_trace',
      evidence_kind: evidenceKind,
      source_name: typeof record.run_id === 'string' ? record.run_id : undefined,
      source_mode: mode,
      imported_at: new Date().toISOString(),
      executed: Boolean(environment.executed),
      raw_event_count: timeline.length,
      api_calls: aggregateApiEvents(apiResolution),
      memory_regions: memoryRegions
        .map((entry) => normalizeRegion(entry))
        .filter((item): item is NormalizedDynamicTraceMemoryRegion => Boolean(item)),
      modules: [],
      strings: dedupeStrings(
        timeline
          .map((entry) => asObject(entry))
          .filter((item): item is Record<string, unknown> => Boolean(item))
          .map((item) => readFirstString(item, ['indicator']) || '')
      ),
      stages: dedupeStrings(
        executionHypotheses
          .map((entry) => asObject(entry))
          .filter((item): item is Record<string, unknown> => Boolean(item))
          .map((item) => readFirstString(item, ['stage']) || '')
      ),
      risk_hints: dedupeStrings([
        readFirstString(asObject(record.risk) || {}, ['level']) || '',
        ...toStringArray(record.warnings),
      ]),
      notes: [
        typeof record.mode === 'string' ? `Imported sandbox trace from mode=${record.mode}` : 'Imported sandbox trace',
      ],
    }
  }

  return null
}

export function summarizeDynamicTrace(trace: NormalizedDynamicTrace): DynamicTraceSummary {
  const observedApis = trace.api_calls.map((item) => item.api)
  const highSignalApis = observedApis.filter((item) => HIGH_SIGNAL_APIS.has(normalizeApiName(item)))
  const memoryRegions = trace.memory_regions.map((item) => item.purpose || item.region_type)
  const regionTypes = trace.memory_regions.map((item) => item.region_type)
  const protections = trace.memory_regions.map((item) => item.protection || '')
  const addressRanges = trace.memory_regions
    .map((item) => {
      if (!item.base_address) {
        return ''
      }
      if (!item.size) {
        return item.base_address
      }
      const start = Number.parseInt(item.base_address.replace(/^0x/i, ''), 16)
      if (!Number.isFinite(start)) {
        return item.base_address
      }
      return `${item.base_address}-0x${(start + item.size).toString(16)}`
    })
    .filter((item) => item.length > 0)
  const regionOwners = trace.memory_regions.map((item) => item.module_name || '')
  const segmentNames = trace.memory_regions.map((item) => item.segment_name || '')
  const evidence: string[] = []

  evidence.push(
    trace.executed
      ? `Imported runtime trace observed ${trace.api_calls.length} unique API(s).`
      : `Imported ${trace.evidence_kind} evidence observed ${trace.api_calls.length} unique API(s).`
  )

  if (highSignalApis.length > 0) {
    evidence.push(`High-signal runtime APIs: ${dedupeStrings(highSignalApis, 10).join(', ')}`)
  }
  if (memoryRegions.length > 0) {
    evidence.push(`Memory regions or plans: ${dedupeStrings(memoryRegions, 8).join(', ')}`)
  }
  if (protections.some((item) => item.length > 0)) {
    evidence.push(`Observed protections: ${dedupeStrings(protections, 8).join(', ')}`)
  }
  if (trace.stages.length > 0) {
    evidence.push(`Derived runtime stages: ${trace.stages.join(', ')}`)
  }
  for (const hint of trace.risk_hints) {
    evidence.push(hint)
  }

  return {
    artifact_count: 1,
    executed: trace.executed,
    executed_artifact_count: trace.executed ? 1 : 0,
    api_count: trace.api_calls.length,
    memory_region_count: trace.memory_regions.length,
    stage_count: trace.stages.length,
    observed_apis: dedupeStrings(observedApis, 20),
    high_signal_apis: dedupeStrings(highSignalApis, 12),
    memory_regions: dedupeStrings(memoryRegions, 12),
    region_types: dedupeStrings(regionTypes, 12),
    protections: dedupeStrings(protections, 12),
    address_ranges: dedupeStrings(addressRanges, 12),
    region_owners: dedupeStrings(regionOwners, 12),
    observed_modules: dedupeStrings(trace.modules, 12),
    segment_names: dedupeStrings(segmentNames, 12),
    observed_strings: dedupeStrings(trace.strings, 12),
    stages: trace.stages,
    risk_hints: trace.risk_hints,
    source_formats: [trace.source_format],
    evidence_kinds: [trace.evidence_kind],
    source_names: dedupeStrings(trace.source_name ? [trace.source_name] : []),
    source_modes: dedupeStrings(trace.source_mode ? [trace.source_mode] : []),
    confidence_layers: [
      {
        layer: classifyDynamicEvidenceLayer(trace),
        artifact_count: 1,
        confidence_band: confidenceBandForLayer(classifyDynamicEvidenceLayer(trace)),
        source_formats: [trace.source_format],
        evidence_kinds: [trace.evidence_kind],
        source_names: dedupeStrings(trace.source_name ? [trace.source_name] : []),
        source_modes: dedupeStrings(trace.source_mode ? [trace.source_mode] : []),
        latest_imported_at: trace.imported_at,
        summary: summarizeDynamicEvidenceLayer(
          classifyDynamicEvidenceLayer(trace),
          1,
          dedupeStrings(trace.source_mode ? [trace.source_mode] : [])
        ),
      },
    ],
    earliest_imported_at: trace.imported_at,
    latest_imported_at: trace.imported_at,
    scope_note: 'Runtime evidence currently reflects a single registered artifact.',
    evidence: dedupeStrings(evidence),
    summary:
      trace.executed
        ? `Runtime evidence observed ${trace.api_calls.length} API(s) across ${trace.stages.length || 1} inferred stage(s).`
        : `Imported ${trace.evidence_kind} evidence observed ${trace.api_calls.length} API(s) with ${trace.memory_regions.length} memory-region hint(s).`,
  }
}

export async function loadDynamicTraceEvidence(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadDynamicTraceEvidenceOptions = {}
): Promise<DynamicTraceSummary | null> {
  const artifacts = [
    ...database.findArtifactsByType(sampleId, 'dynamic_trace_json'),
    ...database.findArtifactsByType(sampleId, 'sandbox_trace_json'),
  ]

  if (artifacts.length === 0) {
    return null
  }

  const workspace = await workspaceManager.getWorkspace(sampleId)
  const loadedTraces: LoadedDynamicTraceArtifact[] = []

  for (const artifact of artifacts) {
    try {
      const absPath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const content = await fs.readFile(absPath, 'utf-8')
      const parsed = JSON.parse(content) as unknown
      const normalized =
        normalizeDynamicTraceArtifactPayload(parsed) ||
        normalizeDynamicTrace(parsed, { sourceFormat: 'generic_json', evidenceKind: 'hybrid' })
      const sessionTags = new Set<string>()
      const derivedSessionTag = deriveArtifactSessionTag(artifact.path)
      if (derivedSessionTag) {
        sessionTags.add(derivedSessionTag)
      }
      if (typeof normalized.source_name === 'string' && normalized.source_name.trim().length > 0) {
        sessionTags.add(normalized.source_name.trim())
      }
      const basename = path.basename(artifact.path, path.extname(artifact.path)).trim()
      if (basename.length > 0) {
        sessionTags.add(basename)
      }

      loadedTraces.push({
        artifact,
        normalized,
        session_tags: Array.from(sessionTags),
      })
    } catch {
      continue
    }
  }

  if (loadedTraces.length === 0) {
    return null
  }

  const normalizedSelector = options.sessionTag?.trim().toLowerCase() || null
  const evidenceScope = options.evidenceScope || 'all'
  let selectedTraces = loadedTraces

  if (normalizedSelector) {
    selectedTraces = selectedTraces.filter((item) => {
      if (item.artifact.path.toLowerCase().includes(normalizedSelector)) {
        return true
      }
      return item.session_tags.some((tag) => tag.toLowerCase() === normalizedSelector)
    })
  }

  if (evidenceScope === 'latest' && selectedTraces.length > 1) {
    const latestTimestamp = selectedTraces.reduce((maxValue, item) => {
      const timestamp = new Date(item.artifact.created_at || item.normalized.imported_at).getTime()
      return Number.isFinite(timestamp) && timestamp > maxValue ? timestamp : maxValue
    }, Number.NEGATIVE_INFINITY)

    if (Number.isFinite(latestTimestamp)) {
      selectedTraces = selectedTraces.filter((item) => {
        const timestamp = new Date(item.artifact.created_at || item.normalized.imported_at).getTime()
        return Number.isFinite(timestamp) && latestTimestamp - timestamp <= LATEST_DYNAMIC_EVIDENCE_WINDOW_MS
      })
    }
  }

  if (selectedTraces.length === 0) {
    return null
  }

  const normalizedTraces = selectedTraces.map((item) => item.normalized)

  const aggregated = {
    artifact_count: normalizedTraces.length,
    executed: normalizedTraces.some((item) => item.executed),
    executed_artifact_count: normalizedTraces.filter((item) => item.executed).length,
    observed_apis: dedupeStrings(
      normalizedTraces.flatMap((item) => item.api_calls.map((entry) => entry.api)),
      30
    ),
    memory_regions: dedupeStrings(
      normalizedTraces.flatMap((item) => item.memory_regions.map((entry) => entry.purpose || entry.region_type)),
      20
    ),
    region_types: dedupeStrings(
      normalizedTraces.flatMap((item) => item.memory_regions.map((entry) => entry.region_type)),
      20
    ),
    protections: dedupeStrings(
      normalizedTraces.flatMap((item) => item.memory_regions.map((entry) => entry.protection || '')),
      20
    ),
    address_ranges: dedupeStrings(
      normalizedTraces.flatMap((item) =>
        item.memory_regions.map((entry) => {
          if (!entry.base_address) {
            return ''
          }
          if (!entry.size) {
            return entry.base_address
          }
          const start = Number.parseInt(entry.base_address.replace(/^0x/i, ''), 16)
          if (!Number.isFinite(start)) {
            return entry.base_address
          }
          return `${entry.base_address}-0x${(start + entry.size).toString(16)}`
        })
      ),
      20
    ),
    region_owners: dedupeStrings(
      normalizedTraces.flatMap((item) => item.memory_regions.map((entry) => entry.module_name || '')),
      20
    ),
    observed_modules: dedupeStrings(
      normalizedTraces.flatMap((item) => [
        ...item.modules,
        ...item.memory_regions.map((entry) => entry.module_name || ''),
      ]),
      20
    ),
    segment_names: dedupeStrings(
      normalizedTraces.flatMap((item) => item.memory_regions.map((entry) => entry.segment_name || '')),
      20
    ),
    observed_strings: dedupeStrings(
      normalizedTraces.flatMap((item) => item.strings),
      20
    ),
    stages: dedupeStrings(normalizedTraces.flatMap((item) => item.stages), 20),
    risk_hints: dedupeStrings(normalizedTraces.flatMap((item) => item.risk_hints), 20),
    source_formats: dedupeStrings(normalizedTraces.map((item) => item.source_format), 12),
    evidence_kinds: dedupeStrings(normalizedTraces.map((item) => item.evidence_kind), 12),
    source_modes: dedupeStrings(
      normalizedTraces.map((item) => item.source_mode || '').filter((item) => item.length > 0),
      12
    ),
    source_names: dedupeStrings(
      normalizedTraces
        .map((item) => item.source_name || '')
        .filter((item) => item.length > 0),
      20
    ),
    imported_at: normalizedTraces
      .map((item) => item.imported_at)
      .filter((item) => item && item.length > 0)
      .sort(),
  }

  const layerBuckets = new Map<
    DynamicEvidenceLayerName,
    {
      artifact_count: number
      source_formats: Set<string>
      evidence_kinds: Set<string>
      source_names: Set<string>
      source_modes: Set<string>
      latest_imported_at: string | null
    }
  >()

  for (const trace of normalizedTraces) {
    const layer = classifyDynamicEvidenceLayer(trace)
    const existing = layerBuckets.get(layer) || {
      artifact_count: 0,
      source_formats: new Set<string>(),
      evidence_kinds: new Set<string>(),
      source_names: new Set<string>(),
      source_modes: new Set<string>(),
      latest_imported_at: null,
    }
    existing.artifact_count += 1
    existing.source_formats.add(trace.source_format)
    existing.evidence_kinds.add(trace.evidence_kind)
    if (trace.source_name) {
      existing.source_names.add(trace.source_name)
    }
    if (trace.source_mode) {
      existing.source_modes.add(trace.source_mode)
    }
    if (!existing.latest_imported_at || trace.imported_at > existing.latest_imported_at) {
      existing.latest_imported_at = trace.imported_at
    }
    layerBuckets.set(layer, existing)
  }

  const confidenceLayers: DynamicEvidenceLayerSummary[] = Array.from(layerBuckets.entries())
    .map(([layer, bucket]) => ({
      layer,
      artifact_count: bucket.artifact_count,
      confidence_band: confidenceBandForLayer(layer),
      source_formats: dedupeStrings(Array.from(bucket.source_formats), 12),
      evidence_kinds: dedupeStrings(Array.from(bucket.evidence_kinds), 12),
      source_names: dedupeStrings(Array.from(bucket.source_names), 12),
      source_modes: dedupeStrings(Array.from(bucket.source_modes), 12),
      latest_imported_at: bucket.latest_imported_at,
      summary: summarizeDynamicEvidenceLayer(
        layer,
        bucket.artifact_count,
        dedupeStrings(Array.from(bucket.source_modes), 12)
      ),
    }))
    .sort((left, right) => {
      const rank: Record<DynamicEvidenceLayerName, number> = {
        executed_trace: 0,
        safe_simulation: 1,
        memory_or_hybrid: 2,
      }
      return rank[left.layer] - rank[right.layer]
    })

  const highSignalApis = aggregated.observed_apis.filter((item) =>
    HIGH_SIGNAL_APIS.has(normalizeApiName(item))
  )
  const evidence = dedupeStrings(
    [
      ...normalizedTraces.flatMap((item) => summarizeDynamicTrace(item).evidence),
      confidenceLayers.length > 0
        ? `Runtime evidence layers: ${confidenceLayers
            .map((item) => `${item.layer}(${item.artifact_count})`)
            .join(', ')}`
        : '',
      normalizedTraces.length > 1
        ? 'Runtime evidence is aggregated across registered artifacts for this sample and is not limited to the current call.'
        : '',
    ],
    24
  )

  const earliestImportedAt = aggregated.imported_at[0] || null
  const latestImportedAt =
    aggregated.imported_at.length > 0 ? aggregated.imported_at[aggregated.imported_at.length - 1] : null
  const scopeNote =
    evidenceScope === 'latest'
      ? `Runtime evidence is limited to the latest artifact window (${selectedTraces.length}/${loadedTraces.length} artifact(s), window=${LATEST_DYNAMIC_EVIDENCE_WINDOW_MS}ms).`
      : normalizedSelector
        ? `Runtime evidence is limited to session selector "${options.sessionTag}" (${selectedTraces.length}/${loadedTraces.length} artifact(s)).`
        : normalizedTraces.length > 1
          ? 'Runtime evidence is aggregated across multiple registered artifacts and may include historical imports, simulations, and executed traces.'
          : 'Runtime evidence currently reflects a single registered artifact for this sample.'

  return {
    artifact_count: aggregated.artifact_count,
    artifact_ids: Array.from(new Set(selectedTraces.map((item) => item.artifact.id))),
    executed: aggregated.executed,
    executed_artifact_count: aggregated.executed_artifact_count,
    api_count: aggregated.observed_apis.length,
    memory_region_count: aggregated.memory_regions.length,
    stage_count: aggregated.stages.length,
    observed_apis: aggregated.observed_apis,
    high_signal_apis: dedupeStrings(highSignalApis, 12),
    memory_regions: aggregated.memory_regions,
    region_types: aggregated.region_types,
    protections: aggregated.protections,
    address_ranges: aggregated.address_ranges,
    region_owners: aggregated.region_owners,
    observed_modules: aggregated.observed_modules,
    segment_names: aggregated.segment_names,
    observed_strings: aggregated.observed_strings,
    stages: aggregated.stages,
    risk_hints: aggregated.risk_hints,
    source_formats: aggregated.source_formats,
    evidence_kinds: aggregated.evidence_kinds,
    source_modes: aggregated.source_modes,
    source_names: aggregated.source_names,
    confidence_layers: confidenceLayers,
    earliest_imported_at: earliestImportedAt,
    latest_imported_at: latestImportedAt,
    scope_note: scopeNote,
    evidence_scope: evidenceScope,
    session_selector: options.sessionTag || null,
    session_tags: dedupeStrings(selectedTraces.flatMap((item) => item.session_tags), 20),
    evidence,
    summary: aggregated.executed
      ? `Imported runtime evidence from ${aggregated.artifact_count} artifact(s) observed ${aggregated.observed_apis.length} API(s).`
      : `Imported memory/runtime evidence from ${aggregated.artifact_count} artifact(s) observed ${aggregated.observed_apis.length} API(s).`,
  }
}
