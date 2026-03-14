/**
 * dynamic.memory.import tool
 * Import minidump or raw process-memory snapshots and normalize them into runtime evidence.
 */

import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  normalizeDynamicTrace,
  summarizeDynamicTrace,
  type DynamicTraceSourceFormat,
} from '../dynamic-trace.js'

const TOOL_NAME = 'dynamic.memory.import'

const DynamicMemoryImportInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  path: z.string().describe('Path to a minidump or raw process-memory snapshot'),
  format: z
    .enum(['auto', 'minidump', 'process_memory', 'raw_dump'])
    .optional()
    .default('auto')
    .describe('Format hint for the memory snapshot'),
  trace_name: z.string().optional().describe('Optional source name used in persisted artifact naming'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist copied raw dump plus normalized runtime-evidence artifact'),
  register_analysis: z
    .boolean()
    .optional()
    .default(true)
    .describe('Insert a completed analysis row for the imported memory evidence'),
  min_string_length: z
    .number()
    .int()
    .min(4)
    .max(32)
    .optional()
    .default(5)
    .describe('Minimum extracted string length'),
  max_strings: z
    .number()
    .int()
    .min(50)
    .max(5000)
    .optional()
    .default(800)
    .describe('Maximum number of strings retained from the snapshot'),
  context_window_bytes: z
    .number()
    .int()
    .min(32)
    .max(4096)
    .optional()
    .default(192)
    .describe('Maximum offset gap used to group nearby strings into memory windows'),
})

type DynamicMemoryImportInput = z.infer<typeof DynamicMemoryImportInputSchema>

const DynamicMemoryImportOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      ingest_id: z.string(),
      format: z.string(),
      evidence_kind: z.literal('memory_snapshot'),
      executed: z.boolean(),
      extracted_string_count: z.number().int().nonnegative(),
      context_window_count: z.number().int().nonnegative(),
      summary: z.object({
        artifact_count: z.number(),
        executed: z.boolean(),
        executed_artifact_count: z.number().optional(),
        api_count: z.number(),
        memory_region_count: z.number(),
        stage_count: z.number(),
        observed_apis: z.array(z.string()),
        high_signal_apis: z.array(z.string()),
        memory_regions: z.array(z.string()),
        region_types: z.array(z.string()).optional(),
        protections: z.array(z.string()).optional(),
        address_ranges: z.array(z.string()).optional(),
        region_owners: z.array(z.string()).optional(),
        observed_modules: z.array(z.string()).optional(),
        segment_names: z.array(z.string()).optional(),
        stages: z.array(z.string()),
        risk_hints: z.array(z.string()),
        source_formats: z.array(z.string()).optional(),
        evidence_kinds: z.array(z.string()).optional(),
        source_names: z.array(z.string()).optional(),
        evidence: z.array(z.string()),
        summary: z.string(),
      }),
      normalized_trace: z.any(),
      analysis_id: z.string().optional(),
      raw_artifact: z.any().optional(),
      trace_artifact: z.any().optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const dynamicMemoryImportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Import a minidump or raw process-memory snapshot, extract runtime-relevant strings/API evidence, and persist normalized memory-snapshot runtime artifacts.',
  inputSchema: DynamicMemoryImportInputSchema,
  outputSchema: DynamicMemoryImportOutputSchema,
}

interface ExtractedString {
  offset: number
  value: string
  encoding: 'ascii' | 'utf16le'
}

interface ApiAggregate {
  api: string
  count: number
  confidence: number
  sources: string[]
}

interface MemoryRegionHint {
  region_type: string
  purpose: string
  source: string
  confidence: number
  base_address: string
  size: number
  indicators: string[]
  protection?: string
  module_name?: string
  segment_name?: string
}

function inferWindowProtection(regionType: string, indicators: string[]): string {
  const corpus = `${regionType} ${indicators.join(' ')}`.toLowerCase()
  if (/api_resolution|dispatch/.test(corpus)) {
    return 'read_only_data'
  }
  if (/process_operation|thread|virtualalloc|writeprocessmemory|setthreadcontext|resumethread/.test(corpus)) {
    return 'read_write_control'
  }
  if (/file_operation|registry_operation/.test(corpus)) {
    return 'read_write_plan'
  }
  if (/network_operation|http|socket|connect|send|recv/.test(corpus)) {
    return 'read_write_buffer'
  }
  if (/environment_probe|anti_analysis/.test(corpus)) {
    return 'read_only_probe'
  }
  return 'read_only_snapshot'
}

const API_CANDIDATES = [
  'GetProcAddress',
  'LoadLibraryA',
  'LoadLibraryW',
  'LoadLibraryExA',
  'LoadLibraryExW',
  'GetModuleHandleA',
  'GetModuleHandleW',
  'OpenProcess',
  'OpenProcessToken',
  'CreateProcessA',
  'CreateProcessW',
  'ReadProcessMemory',
  'WriteProcessMemory',
  'VirtualAllocEx',
  'VirtualProtectEx',
  'CreateRemoteThread',
  'ResumeThread',
  'SetThreadContext',
  'NtQueryInformationProcess',
  'NtQuerySystemInformation',
  'CreateFileA',
  'CreateFileW',
  'ReadFile',
  'WriteFile',
  'DeleteFileA',
  'DeleteFileW',
  'CopyFileA',
  'CopyFileW',
  'FindFirstFileA',
  'FindFirstFileW',
  'FindNextFileA',
  'FindNextFileW',
  'RegOpenKeyExA',
  'RegOpenKeyExW',
  'RegCreateKeyExA',
  'RegCreateKeyExW',
  'RegSetValueExA',
  'RegSetValueExW',
  'InternetOpenA',
  'InternetOpenW',
  'InternetConnectA',
  'InternetConnectW',
  'HttpSendRequestA',
  'HttpSendRequestW',
  'WinHttpSendRequest',
  'socket',
  'connect',
  'send',
  'recv',
]

function sanitizeName(value: string | undefined): string {
  const base = (value || 'memory').trim().toLowerCase()
  const normalized = base.replace(/[^a-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 48) : 'memory'
}

function isPrintableAscii(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e
}

function dedupeStrings(values: string[], limit?: number): string[] {
  const unique = Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
  return typeof limit === 'number' ? unique.slice(0, limit) : unique
}

function inferModuleNameFromStrings(values: string[]): string | undefined {
  for (const value of values) {
    const match = value.match(/\b([A-Za-z0-9_.-]+\.(?:dll|exe|sys))\b/i)
    if (match?.[1]) {
      return match[1]
    }
  }
  return undefined
}

function detectEmbeddedPeOffsets(data: Buffer, maxOffsets = 6): number[] {
  const offsets: number[] = []
  for (let index = 0; index <= data.length - 0x40; index += 1) {
    if (data[index] !== 0x4d || data[index + 1] !== 0x5a) {
      continue
    }
    const peOffset = data.readUInt32LE(index + 0x3c)
    const signatureOffset = index + peOffset
    if (signatureOffset + 4 > data.length) {
      continue
    }
    if (
      data[signatureOffset] === 0x50 &&
      data[signatureOffset + 1] === 0x45 &&
      data[signatureOffset + 2] === 0x00 &&
      data[signatureOffset + 3] === 0x00
    ) {
      offsets.push(index)
      if (offsets.length >= maxOffsets) {
        break
      }
      index += 1
    }
  }
  return offsets
}

function detectMemoryFormat(filePath: string, data: Buffer, hint: DynamicMemoryImportInput['format']): DynamicTraceSourceFormat {
  if (hint && hint !== 'auto') {
    return hint
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'MDMP') {
    return 'minidump'
  }

  const ext = path.extname(filePath).toLowerCase()
  if (ext === '.dmp' || ext === '.mdmp' || ext === '.dump') {
    return 'minidump'
  }
  if (ext === '.mem' || ext === '.pmem' || ext === '.vmem') {
    return 'process_memory'
  }
  return 'raw_dump'
}

function extractAsciiStrings(data: Buffer, minLen: number, maxItems: number): ExtractedString[] {
  const results: ExtractedString[] = []
  let start = -1

  for (let index = 0; index <= data.length; index += 1) {
    const current = index < data.length ? data[index] : 0
    if (index < data.length && isPrintableAscii(current)) {
      if (start === -1) {
        start = index
      }
      continue
    }

    if (start !== -1) {
      const length = index - start
      if (length >= minLen) {
        results.push({
          offset: start,
          value: data.subarray(start, index).toString('ascii'),
          encoding: 'ascii',
        })
        if (results.length >= maxItems) {
          return results
        }
      }
      start = -1
    }
  }

  return results
}

function extractUtf16Strings(data: Buffer, minLen: number, maxItems: number): ExtractedString[] {
  const results: ExtractedString[] = []
  let start = -1
  let charCount = 0
  let index = 0

  while (index + 1 < data.length) {
    const low = data[index]
    const high = data[index + 1]
    if (isPrintableAscii(low) && high === 0x00) {
      if (start === -1) {
        start = index
      }
      charCount += 1
      index += 2
      continue
    }

    if (start !== -1 && charCount >= minLen) {
      results.push({
        offset: start,
        value: data.subarray(start, index).toString('utf16le'),
        encoding: 'utf16le',
      })
      if (results.length >= maxItems) {
        return results
      }
    }
    start = -1
    charCount = 0
    index += 1
  }

  if (start !== -1 && charCount >= minLen && results.length < maxItems) {
    results.push({
      offset: start,
      value: data.subarray(start, index).toString('utf16le'),
      encoding: 'utf16le',
    })
  }

  return results
}

function extractStrings(
  data: Buffer,
  minLen: number,
  maxItems: number
): ExtractedString[] {
  const half = Math.max(50, Math.floor(maxItems / 2))
  const entries = [...extractAsciiStrings(data, minLen, half), ...extractUtf16Strings(data, minLen, half)]
  return entries
    .sort((left, right) => left.offset - right.offset)
    .slice(0, maxItems)
}

function extractApisFromString(value: string): string[] {
  const hits: string[] = []
  for (const api of API_CANDIDATES) {
    const pattern = new RegExp(`\\b${api.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\b`, 'i')
    if (pattern.test(value)) {
      hits.push(api)
    }
  }
  return dedupeStrings(hits)
}

function aggregateApiStrings(strings: ExtractedString[]): ApiAggregate[] {
  const aggregates = new Map<string, ApiAggregate>()

  for (const entry of strings) {
    const apis = extractApisFromString(entry.value)
    for (const api of apis) {
      const existing = aggregates.get(api)
      const source = `offset:0x${entry.offset.toString(16)}:${entry.encoding}`
      if (existing) {
        existing.count += 1
        existing.sources = dedupeStrings([...existing.sources, source], 6)
        existing.confidence = Math.min(0.92, existing.confidence + 0.03)
      } else {
        aggregates.set(api, {
          api,
          count: 1,
          confidence: /Process|Thread|GetProcAddress|LoadLibrary|NtQuery/i.test(api) ? 0.82 : 0.72,
          sources: [source],
        })
      }
    }
  }

  return Array.from(aggregates.values()).sort((left, right) => {
    if (right.count !== left.count) {
      return right.count - left.count
    }
    return right.confidence - left.confidence
  })
}

function classifyWindow(apis: string[]): { regionType: string; purpose: string } {
  const corpus = apis.join(' ')
  if (/\b(GetProcAddress|LoadLibrary|GetModuleHandle)\b/i.test(corpus)) {
    return {
      regionType: 'api_resolution_table',
      purpose: 'dynamic_api_table',
    }
  }
  if (/\b(OpenProcess|ReadProcessMemory|WriteProcessMemory|SetThreadContext|ResumeThread|CreateRemoteThread|VirtualAllocEx|CreateProcess)\b/i.test(corpus)) {
    return {
      regionType: 'process_operation_plan',
      purpose: 'remote_process_access',
    }
  }
  if (/\b(CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|FindFirstFile|FindNextFile)\b/i.test(corpus)) {
    return {
      regionType: 'file_operation_plan',
      purpose: 'file_dispatch_table',
    }
  }
  if (/\b(RegOpenKey|RegCreateKey|RegSetValue)\b/i.test(corpus)) {
    return {
      regionType: 'registry_operation_plan',
      purpose: 'registry_staging',
    }
  }
  if (/\b(InternetOpen|InternetConnect|HttpSendRequest|WinHttp|socket|connect|send|recv)\b/i.test(corpus)) {
    return {
      regionType: 'network_operation_plan',
      purpose: 'network_dispatch',
    }
  }
  if (/\b(NtQueryInformationProcess|NtQuerySystemInformation)\b/i.test(corpus)) {
    return {
      regionType: 'environment_probe',
      purpose: 'anti_analysis_observations',
    }
  }
  return {
    regionType: 'memory_string_window',
    purpose: 'snapshot_context_window',
  }
}

function buildContextRegions(
  strings: ExtractedString[],
  contextWindowBytes: number
): MemoryRegionHint[] {
  if (strings.length === 0) {
    return []
  }

  const windows: ExtractedString[][] = []
  let current: ExtractedString[] = [strings[0]]

  for (const entry of strings.slice(1)) {
    const previous = current[current.length - 1]
    if (entry.offset - previous.offset <= contextWindowBytes) {
      current.push(entry)
      continue
    }
    windows.push(current)
    current = [entry]
  }
  windows.push(current)

  return windows
    .map((windowEntries) => {
      const apis = dedupeStrings(windowEntries.flatMap((entry) => extractApisFromString(entry.value)), 12)
      const indicators = dedupeStrings(
        [...apis, ...windowEntries.slice(0, 4).map((entry) => entry.value)],
        10
      )
      const moduleName = inferModuleNameFromStrings(indicators)
      const classification = classifyWindow(apis)
      const start = windowEntries[0].offset
      const end = windowEntries[windowEntries.length - 1].offset
      return {
        region_type: classification.regionType,
        purpose: classification.purpose,
        source: 'memory_snapshot_window',
        confidence: Number(
          Math.min(0.9, 0.54 + Math.min(0.18, apis.length * 0.06) + Math.min(0.12, windowEntries.length * 0.02)).toFixed(2)
        ),
        base_address: `0x${start.toString(16)}`,
        size: Math.max(1, end - start),
        indicators,
        protection: inferWindowProtection(classification.regionType, indicators),
        module_name: moduleName,
        segment_name: moduleName ? 'string_window' : undefined,
      }
    })
    .filter((item) => item.indicators.length > 0)
    .slice(0, 16)
}

function buildSyntheticSegments(
  data: Buffer,
  strings: ExtractedString[],
  effectiveFormat: DynamicTraceSourceFormat
): MemoryRegionHint[] {
  const segments: MemoryRegionHint[] = []
  const globalModuleHint = inferModuleNameFromStrings(strings.map((item) => item.value))

  if (effectiveFormat === 'minidump' && data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'MDMP') {
    segments.push({
      region_type: 'minidump_header',
      purpose: 'minidump_container',
      source: 'memory_snapshot_header',
      confidence: 0.98,
      base_address: '0x0',
      size: Math.min(data.length, 256),
      indicators: ['MDMP', 'minidump'],
      protection: 'file_container',
      module_name: globalModuleHint,
      segment_name: 'header',
    })
  }

  const peOffsets = detectEmbeddedPeOffsets(data)
  for (const offset of peOffsets) {
    const nearbyStrings = strings
      .filter((item) => Math.abs(item.offset - offset) <= 0x2000)
      .map((item) => item.value)
    const moduleName = inferModuleNameFromStrings(nearbyStrings) || globalModuleHint
    segments.push({
      region_type: 'mapped_pe_image',
      purpose: 'embedded_module_image',
      source: 'memory_snapshot_scan',
      confidence: 0.88,
      base_address: `0x${offset.toString(16)}`,
      size: Math.min(Math.max(0x400, data.length - offset), 0x4000),
      indicators: dedupeStrings(['MZ', 'PE', ...(moduleName ? [moduleName] : [])], 6),
      protection: 'r-x_image',
      module_name: moduleName,
      segment_name: '.image',
    })
  }

  return segments
}

function buildRiskHints(format: DynamicTraceSourceFormat, apis: ApiAggregate[]): string[] {
  const apiNames = apis.map((item) => item.api)
  const hints: string[] = []

  if (format === 'minidump') {
    hints.push('Memory evidence originated from a minidump; execution was not directly replayed.')
  } else {
    hints.push('Memory evidence originated from a process-memory snapshot; execution was not directly replayed.')
  }

  if (apiNames.some((item) => /WriteProcessMemory|ReadProcessMemory|VirtualAllocEx|CreateRemoteThread/i.test(item))) {
    hints.push('Process-memory manipulation indicators were recovered from memory strings.')
  }
  if (apiNames.some((item) => /GetProcAddress|LoadLibrary/i.test(item))) {
    hints.push('Dynamic API resolution indicators were recovered from memory strings.')
  }
  if (apiNames.some((item) => /NtQueryInformationProcess|NtQuerySystemInformation/i.test(item))) {
    hints.push('Anti-analysis or environment-query indicators were recovered from memory strings.')
  }

  return dedupeStrings(hints, 8)
}

function buildNormalizedMemoryTrace(
  input: DynamicMemoryImportInput,
  effectiveFormat: DynamicTraceSourceFormat,
  strings: ExtractedString[],
  apiAggregates: ApiAggregate[],
  memoryRegions: MemoryRegionHint[],
  segments: MemoryRegionHint[]
) {
  const rawRecord = {
    executed: false,
    api_calls: apiAggregates.map((item) => ({
      api: item.api,
      count: item.count,
      confidence: item.confidence,
      sources: item.sources,
    })),
    memory_regions: memoryRegions,
    segments,
    modules: dedupeStrings(
      [...memoryRegions.map((item) => item.module_name || ''), ...segments.map((item) => item.module_name || '')],
      24
    ),
    strings: strings.slice(0, 120).map((item) => item.value),
    risk_hints: buildRiskHints(effectiveFormat, apiAggregates),
    notes: [
      `Imported ${effectiveFormat} memory snapshot from ${path.basename(input.path)}`,
      `Recovered ${apiAggregates.length} API indicator(s) from ${strings.length} extracted string(s).`,
    ],
  }

  return normalizeDynamicTrace(rawRecord, {
    sourceFormat: effectiveFormat,
    evidenceKind: 'memory_snapshot',
    sourceName: input.trace_name || path.basename(input.path),
  })
}

export function createDynamicMemoryImportHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = DynamicMemoryImportInputSchema.parse(args)
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

      const rawData = await fs.readFile(input.path)
      const effectiveFormat = detectMemoryFormat(input.path, rawData, input.format)
      const strings = extractStrings(rawData, input.min_string_length, input.max_strings)
      const apiAggregates = aggregateApiStrings(strings)
      const memoryRegions = buildContextRegions(strings, input.context_window_bytes)
      const segments = buildSyntheticSegments(rawData, strings, effectiveFormat)
      const normalizedTrace = buildNormalizedMemoryTrace(
        input,
        effectiveFormat,
        strings,
        apiAggregates,
        memoryRegions,
        segments
      )
      const summary = summarizeDynamicTrace(normalizedTrace)

      const warnings: string[] = [
        'Imported evidence does not prove full execution; treat it as memory-snapshot evidence until corroborated.',
      ]
      if (apiAggregates.length === 0) {
        warnings.push('No strong API indicators were recovered from the memory snapshot; confidence is string-window limited.')
      }

      const artifacts: ArtifactRef[] = []
      let rawArtifact: ArtifactRef | undefined
      let traceArtifact: ArtifactRef | undefined
      let analysisId: string | undefined

      if (input.persist_artifact) {
        const workspace = await workspaceManager.createWorkspace(input.sample_id)
        const reportDir = path.join(workspace.reports, 'dynamic')
        await fs.mkdir(reportDir, { recursive: true })

        const timestamp = Date.now()
        const sourceExt = path.extname(input.path) || '.bin'
        const rawFileName = `memory_snapshot_${sanitizeName(input.trace_name || path.basename(input.path))}_${timestamp}${sourceExt}`
        const rawAbsPath = path.join(reportDir, rawFileName)
        await fs.writeFile(rawAbsPath, rawData)

        const rawArtifactId = randomUUID()
        const rawSha256 = createHash('sha256').update(rawData).digest('hex')
        const rawRelativePath = `reports/dynamic/${rawFileName}`
        database.insertArtifact({
          id: rawArtifactId,
          sample_id: input.sample_id,
          type: 'raw_dump',
          path: rawRelativePath,
          sha256: rawSha256,
          mime: 'application/octet-stream',
          created_at: new Date().toISOString(),
        })
        rawArtifact = {
          id: rawArtifactId,
          type: 'raw_dump',
          path: rawRelativePath,
          sha256: rawSha256,
          mime: 'application/octet-stream',
        }
        artifacts.push(rawArtifact)

        const traceFileName = `memory_trace_${sanitizeName(input.trace_name || path.basename(input.path))}_${timestamp}.json`
        const traceAbsPath = path.join(reportDir, traceFileName)
        const traceSerialized = JSON.stringify(normalizedTrace, null, 2)
        await fs.writeFile(traceAbsPath, traceSerialized, 'utf-8')

        const traceArtifactId = randomUUID()
        const traceSha256 = createHash('sha256').update(traceSerialized).digest('hex')
        const traceRelativePath = `reports/dynamic/${traceFileName}`
        database.insertArtifact({
          id: traceArtifactId,
          sample_id: input.sample_id,
          type: 'dynamic_trace_json',
          path: traceRelativePath,
          sha256: traceSha256,
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })
        traceArtifact = {
          id: traceArtifactId,
          type: 'dynamic_trace_json',
          path: traceRelativePath,
          sha256: traceSha256,
          mime: 'application/json',
        }
        artifacts.push(traceArtifact)
      }

      if (input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'memory_snapshot_import',
          backend: 'memory_snapshot_import',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            format: effectiveFormat,
            evidence_kind: normalizedTrace.evidence_kind,
            executed: normalizedTrace.executed,
            summary,
            raw_artifact_id: rawArtifact?.id,
            trace_artifact_id: traceArtifact?.id,
          }),
          metrics_json: JSON.stringify({
            extracted_string_count: strings.length,
            api_count: summary.api_count,
            memory_region_count: summary.memory_region_count,
            stage_count: summary.stage_count,
          }),
        })
      }

      return {
        ok: true,
        data: {
          ingest_id: randomUUID(),
          format: effectiveFormat,
          evidence_kind: 'memory_snapshot',
          executed: false,
          extracted_string_count: strings.length,
          context_window_count: memoryRegions.length,
          summary,
          normalized_trace: normalizedTrace,
          analysis_id: analysisId,
          raw_artifact: rawArtifact,
          trace_artifact: traceArtifact,
        },
        warnings,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
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
