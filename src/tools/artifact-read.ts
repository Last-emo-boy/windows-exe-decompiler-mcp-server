/**
 * artifact.read tool implementation
 * Read artifact metadata and optional file content directly via MCP.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { dedupe } from '../utils/shared-helpers.js'
import {
  listArtifactInventory,
  normalizeRelativeArtifactPath,
  type ArtifactInventoryItem,
} from '../artifacts/artifact-inventory.js'

const TOOL_NAME = 'artifact.read'
const TOOL_VERSION = '0.1.0'
const SUMMARY_MAX_BYTES = 64 * 1024
const SUMMARY_PREVIEW_CHARS = 2048
const RELATED_ARTIFACT_LIMIT = 8
const JSON_SUMMARY_PARSE_MAX_BYTES = 8 * 1024 * 1024
const STRING_SIGNAL_LIMIT = 25

const TEXT_EXTENSIONS = new Set([
  '.txt',
  '.md',
  '.mmd',
  '.mermaid',
  '.dot',
  '.json',
  '.log',
  '.yaml',
  '.yml',
  '.xml',
  '.svg',
  '.ini',
  '.cfg',
  '.c',
  '.h',
  '.cpp',
  '.hpp',
  '.cs',
  '.py',
  '.js',
  '.ts',
])

export const ArtifactReadInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  artifact_id: z.string().optional().describe('Specific artifact UUID to fetch'),
  artifact_type: z.string().optional().describe('Artifact type to fetch latest match'),
  path: z.string().optional().describe('Artifact relative path to fetch'),
  read_mode: z
    .enum(['profile', 'summary', 'content'])
    .optional()
    .default('content')
    .describe(
      'Low-context read mode. profile returns metadata and related selectors without reading payload; summary reads a bounded preview; content returns artifact content.'
    ),
  include_untracked_files: z
    .boolean()
    .optional()
    .default(true)
    .describe('Allow synthetic inventory entries for untracked files under scan roots'),
  recursive: z
    .boolean()
    .optional()
    .default(true)
    .describe('Recursively scan export roots when include_untracked_files=true'),
  scan_roots: z
    .array(z.string())
    .optional()
    .default(['reports', 'ghidra', 'dotnet'])
    .describe('Workspace subdirectories to scan for untracked artifact files'),
  select_latest: z
    .boolean()
    .optional()
    .default(true)
    .describe('When selector matches multiple artifacts, choose latest (true) or oldest (false)'),
  include_content: z
    .boolean()
    .optional()
    .default(true)
    .describe('Return file content in response payload'),
  max_bytes: z
    .number()
    .int()
    .min(256)
    .max(2 * 1024 * 1024)
    .optional()
    .default(256 * 1024)
    .describe('Maximum bytes to read from artifact file'),
  encoding: z
    .enum(['auto', 'utf8', 'base64'])
    .optional()
    .default('auto')
    .describe('Content encoding mode when include_content=true'),
  parse_json: z
    .boolean()
    .optional()
    .default(false)
    .describe('Parse JSON artifacts into structured object when content is UTF-8'),
  ioc_highlights: z
    .boolean()
    .optional()
    .default(true)
    .describe('Extract IOC highlights from UTF-8 text content'),
})

export type ArtifactReadInput = z.infer<typeof ArtifactReadInputSchema>

export const ArtifactReadOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      tool_version: z.string(),
      artifact: z.object({
        id: z.string(),
        sample_id: z.string(),
        type: z.string(),
        path: z.string(),
        sha256: z.string(),
        mime: z.string().nullable(),
        created_at: z.string(),
      }),
      read_mode: z.enum(['profile', 'summary', 'content']),
      artifact_profile: z.record(z.any()).optional(),
      summary: z.record(z.any()).optional(),
      related_artifacts: z.array(z.record(z.any())).optional(),
      content: z.string().optional(),
      content_encoding: z.enum(['utf8', 'base64']).optional(),
      parsed_json: z.any().optional(),
      highlights: z
        .object({
          urls: z.array(z.string()).optional(),
          ip_addresses: z.array(z.string()).optional(),
          commands: z.array(z.string()).optional(),
          registry_keys: z.array(z.string()).optional(),
          pipes: z.array(z.string()).optional(),
        })
        .optional(),
      bytes_read: z.number(),
      total_size: z.number(),
      truncated: z.boolean(),
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

function looksLikeText(buffer: Buffer): boolean {
  if (buffer.length === 0) {
    return true
  }

  let suspicious = 0
  for (const byte of buffer) {
    if (byte === 0) {
      suspicious += 1
      continue
    }
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) {
      suspicious += 1
    }
  }

  return suspicious / buffer.length < 0.08
}

function isTextArtifact(
  artifact: Pick<ArtifactInventoryItem, 'path' | 'mime'>,
  sample: Buffer
): boolean {
  const extension = path.extname(artifact.path).toLowerCase()
  if (TEXT_EXTENSIONS.has(extension)) {
    return true
  }
  if (artifact.mime && artifact.mime.startsWith('text/')) {
    return true
  }
  if (artifact.mime === 'application/json') {
    return true
  }
  return looksLikeText(sample)
}

function payloadKindFor(
  artifact: Pick<ArtifactInventoryItem, 'path' | 'mime'>,
  sample?: Buffer
): 'json' | 'text' | 'binary' {
  const extension = path.extname(artifact.path).toLowerCase()
  if (artifact.mime === 'application/json' || extension === '.json') {
    return 'json'
  }
  if (!sample) {
    if (TEXT_EXTENSIONS.has(extension) || artifact.mime?.startsWith('text/')) {
      return 'text'
    }
    return 'binary'
  }
  return isTextArtifact(artifact, sample) ? 'text' : 'binary'
}

function suggestedReadMode(
  artifact: Pick<ArtifactInventoryItem, 'type' | 'path' | 'mime'>
): 'profile' | 'summary' | 'content' {
  const normalized = `${artifact.type} ${artifact.path} ${artifact.mime ?? ''}`.toLowerCase()
  if (
    normalized.includes('summary') ||
    normalized.includes('evidence') ||
    normalized.includes('handoff') ||
    normalized.includes('gaps') ||
    normalized.includes('graph') ||
    normalized.includes('sbom') ||
    normalized.includes('yara') ||
    normalized.includes('ioc')
  ) {
    return 'summary'
  }
  if (
    normalized.includes('report') ||
    normalized.includes('html') ||
    normalized.includes('markdown') ||
    normalized.endsWith('.md') ||
    normalized.endsWith('.html')
  ) {
    return 'content'
  }
  return 'profile'
}

function selectArtifact(
  input: ArtifactReadInput,
  artifacts: ArtifactInventoryItem[]
): ArtifactInventoryItem | null {
  const ordered = input.select_latest ? artifacts : [...artifacts].reverse()

  if (input.artifact_id) {
    return ordered.find((item) => item.id === input.artifact_id) || null
  }

  if (input.path) {
    const normalizedPath = normalizeRelativeArtifactPath(input.path)
    return (
      ordered.find((item) => normalizeRelativeArtifactPath(item.path) === normalizedPath) || null
    )
  }

  if (input.artifact_type) {
    return ordered.find((item) => item.type === input.artifact_type) || null
  }

  return ordered[0] || null
}

async function readArtifactPrefix(artifactAbsPath: string, totalSize: number, maxBytes: number) {
  const bytesToRead = Math.min(totalSize, maxBytes)
  if (bytesToRead <= 0) {
    return { buffer: Buffer.alloc(0), bytesRead: 0, truncated: false }
  }

  const handle = await fs.open(artifactAbsPath, 'r')
  try {
    const buffer = Buffer.alloc(bytesToRead)
    const { bytesRead } = await handle.read(buffer, 0, bytesToRead, 0)
    return {
      buffer: buffer.subarray(0, bytesRead),
      bytesRead,
      truncated: totalSize > bytesRead,
    }
  } finally {
    await handle.close()
  }
}

function jsonShape(value: unknown): Record<string, unknown> {
  if (Array.isArray(value)) {
    const first = value.find((item) => item !== null && typeof item === 'object')
    return {
      top_level: 'array',
      item_count: value.length,
      first_item_keys:
        first && typeof first === 'object' && !Array.isArray(first)
          ? Object.keys(first as Record<string, unknown>).slice(0, 25)
          : [],
    }
  }
  if (value !== null && typeof value === 'object') {
    return {
      top_level: 'object',
      keys: Object.keys(value as Record<string, unknown>).slice(0, 40),
    }
  }
  return { top_level: typeof value }
}

function buildArtifactProfile(
  artifact: ArtifactInventoryItem,
  totalSize: number
): Record<string, unknown> {
  const payloadKind = payloadKindFor(artifact)
  const readMode = suggestedReadMode(artifact)
  return {
    schema: 'rikune.artifact_profile.v1',
    artifact_id: artifact.id,
    artifact_type: artifact.type,
    path: artifact.path,
    mime: artifact.mime,
    size_bytes: totalSize,
    tracked: artifact.tracked,
    exists: artifact.exists,
    session_tag: artifact.session_tag,
    retention_bucket: artifact.retention_bucket,
    age_days: artifact.age_days,
    payload_kind: payloadKind,
    suggested_read_mode: readMode,
    read_args: {
      sample_id: artifact.sample_id,
      artifact_id: artifact.id,
      read_mode: readMode,
    },
  }
}

function buildRelatedArtifacts(
  selected: ArtifactInventoryItem,
  artifacts: ArtifactInventoryItem[]
): Array<Record<string, unknown>> {
  return artifacts
    .filter((artifact) => artifact.id !== selected.id)
    .map((artifact) => {
      const sameSession =
        selected.session_tag !== null && artifact.session_tag === selected.session_tag
      const sameType = artifact.type === selected.type
      const score = (sameSession ? 20 : 0) + (sameType ? 8 : 0) + (artifact.exists ? 2 : 0)
      return { artifact, score }
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || b.artifact.created_at.localeCompare(a.artifact.created_at))
    .slice(0, RELATED_ARTIFACT_LIMIT)
    .map(({ artifact }) => ({
      artifact_id: artifact.id,
      artifact_type: artifact.type,
      path: artifact.path,
      mime: artifact.mime,
      tracked: artifact.tracked,
      session_tag: artifact.session_tag,
      suggested_read_mode: suggestedReadMode(artifact),
      read_args: {
        sample_id: artifact.sample_id,
        artifact_id: artifact.id,
        read_mode: suggestedReadMode(artifact),
      },
    }))
}

function summarizeText(content: string): Record<string, unknown> {
  const lines = content.split(/\r?\n/)
  return {
    line_count: lines.length,
    preview: content.slice(0, SUMMARY_PREVIEW_CHARS),
    preview_truncated: content.length > SUMMARY_PREVIEW_CHARS,
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function recordArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          item !== null && typeof item === 'object' && !Array.isArray(item)
      )
    : []
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function extractStringItems(value: unknown): Record<string, unknown>[] {
  const root = asRecord(value)
  const data = asRecord(root.data)
  for (const candidate of [
    recordArray(data.strings),
    recordArray(root.strings),
    recordArray(data.decoded_strings),
    recordArray(root.decoded_strings),
  ]) {
    if (candidate.length > 0) {
      return candidate
    }
  }
  return []
}

function printableAsciiRatio(value: string): number {
  if (value.length === 0) {
    return 0
  }
  let printable = 0
  for (const char of value) {
    const code = char.charCodeAt(0)
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09) {
      printable += 1
    }
  }
  return printable / value.length
}

function scoreStringSignal(value: string, encoding?: string): { score: number; reasons: string[] } {
  const lower = value.toLowerCase()
  const reasons: string[] = []
  let score = 0
  const ratio = printableAsciiRatio(value)

  if (ratio >= 0.9) {
    score += 4
    reasons.push('printable-ascii')
  } else if (ratio < 0.6 && !/https?:\/\//i.test(value)) {
    score -= 8
    reasons.push('low-printable-ratio')
  }

  if (encoding === 'ascii' || encoding === 'utf16le' || encoding === 'utf16be') {
    score += 2
    reasons.push(`encoding:${encoding}`)
  } else if (encoding && !['utf8', 'utf-8'].includes(encoding.toLowerCase())) {
    score -= 2
    reasons.push(`encoding:${encoding}`)
  }

  const semanticTerms = [
    'password',
    'passwd',
    'pass',
    'serial',
    'license',
    'key',
    'flag',
    'correct',
    'wrong',
    'invalid',
    'success',
    'failed',
    'congrat',
    'try again',
    'usage',
    'error',
    'debug',
    'admin',
    'token',
  ]
  for (const term of semanticTerms) {
    if (lower.includes(term)) {
      score += 8
      reasons.push(`keyword:${term}`)
    }
  }

  if (/https?:\/\/|\\\\\.\\pipe\\|hkey_|\\system32\\|\.dll\b|\.exe\b/i.test(value)) {
    score += 7
    reasons.push('ioc-or-platform-string')
  }
  if (/^[A-Za-z0-9_.$?@-]{4,80}$/.test(value)) {
    score += 2
    reasons.push('symbol-like')
  }
  if (value.length > 160) {
    score -= 4
    reasons.push('very-long')
  }
  if (/[\u4e00-\u9fff]/.test(value) && ratio < 0.75) {
    score -= 6
    reasons.push('likely-misdecoded')
  }

  return { score, reasons }
}

function buildStringArtifactSummary(value: unknown): Record<string, unknown> | undefined {
  const strings = extractStringItems(value)
  if (strings.length === 0) {
    return undefined
  }

  type StringSignal = {
    offset: number | undefined
    string: string
    encoding: string | undefined
    score: number
    reasons: string[]
  }

  const encodingCounts: Record<string, number> = {}
  const scored = strings
    .map((item) => {
      const text = stringValue(item.string) ?? stringValue(item.value) ?? stringValue(item.text)
      if (!text) {
        return null
      }
      const encoding = stringValue(item.encoding)
      encodingCounts[encoding ?? 'unknown'] = (encodingCounts[encoding ?? 'unknown'] ?? 0) + 1
      const scored = scoreStringSignal(text, encoding)
      return {
        offset: numberValue(item.offset),
        string: text,
        encoding,
        score: scored.score,
        reasons: scored.reasons,
      }
    })
    .filter((item): item is StringSignal => item !== null)

  const highSignal = scored
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || a.string.length - b.string.length)
    .slice(0, STRING_SIGNAL_LIMIT)
    .map((item) => ({
      ...(item.offset !== undefined ? { offset: item.offset } : {}),
      string: item.string,
      ...(item.encoding ? { encoding: item.encoding } : {}),
      score: item.score,
      reasons: item.reasons.slice(0, 5),
    }))

  return {
    schema: 'rikune.enriched_string_summary.v1',
    total_strings: strings.length,
    scored_strings: scored.length,
    high_signal_count: highSignal.length,
    encoding_counts: encodingCounts,
    high_signal_strings: highSignal,
    noise_filtered_count: scored.filter((item) => item.score <= 0).length,
  }
}

function buildJsonDomainSummary(
  artifact: ArtifactInventoryItem,
  value: unknown
): Record<string, unknown> | undefined {
  if (artifact.type === 'enriched_string_analysis') {
    return buildStringArtifactSummary(value)
  }
  return undefined
}

function buildContentSummary(params: {
  artifact: ArtifactInventoryItem
  sample: Buffer
  content: string
  encoding: 'utf8' | 'base64'
  bytesRead: number
  totalSize: number
  truncated: boolean
  includeHighlights: boolean
  fullJsonShape?: Record<string, unknown>
  jsonDomainSummary?: Record<string, unknown>
  jsonParseSkippedReason?: string
}): Record<string, unknown> {
  const payloadKind = payloadKindFor(params.artifact, params.sample)
  const summary: Record<string, unknown> = {
    schema: 'rikune.artifact_summary.v1',
    artifact_id: params.artifact.id,
    artifact_type: params.artifact.type,
    path: params.artifact.path,
    payload_kind: payloadKind,
    content_encoding: params.encoding,
    bytes_sampled: params.bytesRead,
    total_size: params.totalSize,
    truncated: params.truncated,
  }

  if (params.encoding === 'utf8') {
    Object.assign(summary, summarizeText(params.content))
    if (params.includeHighlights) {
      summary.highlights = extractIOCTextHighlights(params.content)
    }
    if (payloadKind === 'json') {
      if (params.fullJsonShape) {
        summary.json_shape = params.fullJsonShape
      } else if (params.truncated) {
        summary.json_parse_skipped = params.jsonParseSkippedReason || 'summary content truncated'
      } else {
        try {
          summary.json_shape = jsonShape(JSON.parse(params.content))
        } catch (error) {
          summary.json_parse_warning = (error as Error).message
        }
      }
      if (params.jsonDomainSummary) {
        summary.domain_summary = params.jsonDomainSummary
      }
    }
  }

  return summary
}

function extractIOCTextHighlights(content: string): {
  urls?: string[]
  ip_addresses?: string[]
  commands?: string[]
  registry_keys?: string[]
  pipes?: string[]
} {
  const urls = dedupe(content.match(/https?:\/\/[^\s"'<>]+/gi) || []).slice(0, 30)
  const ips = dedupe(content.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).slice(0, 30)
  const registry = dedupe(content.match(/HKEY_[A-Z_]+\\[^\s]+/gi) || []).slice(0, 30)
  const pipes = dedupe(content.match(/\\\\\.\\pipe\\[^\s]+|\\\\pipe\\[^\s]+/gi) || []).slice(0, 30)
  const commandMatches =
    content.match(
      /(?:^|\s)(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)[^\r\n]*/gim
    ) || []
  const commands = dedupe(commandMatches.map((item) => item.trim())).slice(0, 30)

  return {
    urls: urls.length > 0 ? urls : undefined,
    ip_addresses: ips.length > 0 ? ips : undefined,
    commands: commands.length > 0 ? commands : undefined,
    registry_keys: registry.length > 0 ? registry : undefined,
    pipes: pipes.length > 0 ? pipes : undefined,
  }
}

export const artifactReadToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Read artifact metadata/content by sample_id and artifact selector (artifact_id, artifact_type, or path).',
  inputSchema: ArtifactReadInputSchema,
  outputSchema: ArtifactReadOutputSchema,
}

export function createArtifactReadHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = ArtifactReadInputSchema.parse(args)
      const includeContentWasExplicit = Object.prototype.hasOwnProperty.call(
        args,
        'include_content'
      )
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

      const artifacts = await listArtifactInventory(workspaceManager, database, input.sample_id, {
        includeMissing: true,
        includeUntrackedFiles: input.include_untracked_files,
        recursive: input.recursive,
        scanRoots: input.scan_roots,
      })
      if (artifacts.length === 0) {
        return {
          ok: false,
          errors: [`No artifacts found for sample: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const selected = selectArtifact(input, artifacts)
      if (!selected) {
        return {
          ok: false,
          errors: [
            `Artifact not found for selectors: artifact_id=${input.artifact_id || 'n/a'}, artifact_type=${input.artifact_type || 'n/a'}, path=${input.path || 'n/a'}. Try artifacts.list first to enumerate available records.`,
          ],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const artifactAbsPath = workspaceManager.normalizePath(workspace.root, selected.path)
      const warnings: string[] = []
      const readMode = input.read_mode
      const shouldReturnContent = readMode === 'content' && input.include_content
      let totalSize = selected.size_bytes ?? 0
      try {
        const stat = await fs.stat(artifactAbsPath)
        totalSize = stat.size
      } catch (error) {
        if (readMode !== 'profile') {
          return {
            ok: false,
            errors: [`Artifact file not found: ${selected.path}`],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }
        warnings.push('Artifact file is missing; returning profile from inventory metadata only.')
      }

      const responseData: {
        sample_id: string
        tool_version: string
        artifact: {
          id: string
          sample_id: string
          type: string
          path: string
          sha256: string
          mime: string | null
          created_at: string
        }
        read_mode: 'profile' | 'summary' | 'content'
        artifact_profile?: Record<string, unknown>
        summary?: Record<string, unknown>
        related_artifacts?: Array<Record<string, unknown>>
        content?: string
        content_encoding?: 'utf8' | 'base64'
        parsed_json?: unknown
        highlights?: {
          urls?: string[]
          ip_addresses?: string[]
          commands?: string[]
          registry_keys?: string[]
          pipes?: string[]
        }
        bytes_read: number
        total_size: number
        truncated: boolean
      } = {
        sample_id: input.sample_id,
        tool_version: TOOL_VERSION,
        artifact: {
          id: selected.id,
          sample_id: input.sample_id,
          type: selected.type,
          path: selected.path,
          sha256: selected.sha256,
          mime: selected.mime,
          created_at: selected.created_at,
        },
        read_mode: readMode,
        artifact_profile: buildArtifactProfile(selected, totalSize),
        related_artifacts: buildRelatedArtifacts(selected, artifacts),
        bytes_read: 0,
        total_size: totalSize,
        truncated: false,
      }

      const selectorProvided = Boolean(input.artifact_id || input.artifact_type || input.path)
      if (!selectorProvided && artifacts.length > 1) {
        warnings.push(
          `No selector provided; resolved to ${selected.id} (${selected.type}). Use artifact_id/artifact_type/path for deterministic selection.`
        )
      }
      if ('tracked' in selected && selected.tracked === false) {
        warnings.push(
          'Resolved to untracked filesystem artifact; consider registering export artifacts for stable ids.'
        )
      }

      if (readMode === 'profile' && input.include_content === true && includeContentWasExplicit) {
        warnings.push(
          'read_mode=profile ignores include_content=true to keep the response bounded.'
        )
      }

      if (readMode === 'summary' || shouldReturnContent) {
        const maxBytes =
          readMode === 'summary' ? Math.min(input.max_bytes, SUMMARY_MAX_BYTES) : input.max_bytes
        const readResult = await readArtifactPrefix(artifactAbsPath, totalSize, maxBytes)
        responseData.bytes_read = readResult.bytesRead
        responseData.truncated = readResult.truncated

        if (readResult.truncated) {
          warnings.push(
            `Artifact content truncated to ${maxBytes} bytes (total ${totalSize} bytes).`
          )
        }

        let encoding: 'utf8' | 'base64' = 'utf8'
        if (input.encoding === 'base64') {
          encoding = 'base64'
        } else if (input.encoding === 'auto') {
          encoding = isTextArtifact(selected, readResult.buffer) ? 'utf8' : 'base64'
        }

        const renderedContent =
          encoding === 'utf8'
            ? readResult.buffer.toString('utf-8')
            : readResult.buffer.toString('base64')

        let fullJsonShape: Record<string, unknown> | undefined
        let jsonDomainSummary: Record<string, unknown> | undefined
        let jsonParseSkippedReason: string | undefined
        const payloadKind = payloadKindFor(selected, readResult.buffer)
        if (readMode === 'summary' && encoding === 'utf8' && payloadKind === 'json') {
          if (totalSize <= JSON_SUMMARY_PARSE_MAX_BYTES) {
            try {
              const fullJsonText = readResult.truncated
                ? await fs.readFile(artifactAbsPath, 'utf8')
                : renderedContent
              const parsed = JSON.parse(fullJsonText)
              fullJsonShape = jsonShape(parsed)
              jsonDomainSummary = buildJsonDomainSummary(selected, parsed)
            } catch (error) {
              jsonParseSkippedReason = `full JSON parse failed: ${(error as Error).message}`
            }
          } else {
            jsonParseSkippedReason = `artifact exceeds JSON summary parse limit (${JSON_SUMMARY_PARSE_MAX_BYTES} bytes)`
          }
        }

        if (readMode === 'summary') {
          responseData.summary = buildContentSummary({
            artifact: selected,
            sample: readResult.buffer,
            content: renderedContent,
            encoding,
            bytesRead: readResult.bytesRead,
            totalSize,
            truncated: readResult.truncated,
            includeHighlights: input.ioc_highlights,
            fullJsonShape,
            jsonDomainSummary,
            jsonParseSkippedReason,
          })
        }

        if (shouldReturnContent) {
          responseData.content_encoding = encoding
          responseData.content = renderedContent
        }

        if (shouldReturnContent && encoding === 'utf8' && input.parse_json) {
          try {
            responseData.parsed_json = JSON.parse(responseData.content)
          } catch (error) {
            warnings.push(`parse_json enabled but JSON parsing failed: ${(error as Error).message}`)
          }
        }

        if (shouldReturnContent && encoding === 'utf8' && input.ioc_highlights) {
          responseData.highlights = extractIOCTextHighlights(responseData.content)
        }
      }

      return {
        ok: true,
        data: responseData,
        warnings: warnings.length > 0 ? warnings : undefined,
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
