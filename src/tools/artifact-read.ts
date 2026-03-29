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
import {
  listArtifactInventory,
  normalizeRelativeArtifactPath,
  type ArtifactInventoryItem,
} from '../artifact-inventory.js'

const TOOL_NAME = 'artifact.read'
const TOOL_VERSION = '0.1.0'

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
        type: z.string(),
        path: z.string(),
        sha256: z.string(),
        mime: z.string().nullable(),
        created_at: z.string(),
      }),
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

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values))
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
    content.match(/(?:^|\s)(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)[^\r\n]*/gim) ||
    []
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
      const stat = await fs.stat(artifactAbsPath)

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
        bytes_read: 0,
        total_size: stat.size,
        truncated: false,
      }

      const warnings: string[] = []
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

      if (input.include_content) {
        const fileBuffer = await fs.readFile(artifactAbsPath)
        const truncated = fileBuffer.length > input.max_bytes
        const outputBuffer = truncated ? fileBuffer.subarray(0, input.max_bytes) : fileBuffer
        responseData.bytes_read = outputBuffer.length
        responseData.truncated = truncated

        if (truncated) {
          warnings.push(
            `Artifact content truncated to ${input.max_bytes} bytes (total ${fileBuffer.length} bytes).`
          )
        }

        let encoding: 'utf8' | 'base64' = 'utf8'
        if (input.encoding === 'base64') {
          encoding = 'base64'
        } else if (input.encoding === 'auto') {
          encoding = isTextArtifact(selected, outputBuffer) ? 'utf8' : 'base64'
        }

        responseData.content_encoding = encoding
        responseData.content =
          encoding === 'utf8' ? outputBuffer.toString('utf-8') : outputBuffer.toString('base64')

        if (encoding === 'utf8' && input.parse_json) {
          try {
            responseData.parsed_json = JSON.parse(responseData.content)
          } catch (error) {
            warnings.push(`parse_json enabled but JSON parsing failed: ${(error as Error).message}`)
          }
        }

        if (encoding === 'utf8' && input.ioc_highlights) {
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
