import { execFile } from 'child_process'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { config } from '../config.js'
import { resolveDieCli, type ExternalExecutableResolution } from '../static-backend-discovery.js'
import {
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
} from '../setup-guidance.js'
import {
  buildToolchainConfidenceSemantics,
  ConfidenceSemanticsSchema,
} from '../confidence-semantics.js'
import {
  COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
  persistStaticAnalysisJsonArtifact,
} from '../static-analysis-artifacts.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'

const TOOL_NAME = 'compiler.packer.detect'
const execFileAsync = promisify(execFile)

const AttributionFindingSchema = z.object({
  name: z.string(),
  category: z.enum(['compiler', 'packer', 'protector', 'file_type', 'unknown']),
  confidence: z.number().min(0).max(1),
  evidence_summary: z.string(),
  source: z.string(),
})

const BackendSchema = z.object({
  available: z.boolean(),
  source: z.string().nullable(),
  path: z.string().nullable(),
  version: z.string().nullable(),
  checked_candidates: z.array(z.string()),
  error: z.string().nullable(),
})

export const compilerPackerDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .default(config.workers.static.dieTimeout)
    .describe('Timeout for Detect It Easy execution in seconds'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized compiler/packer attribution into reports/static_analysis'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed analysis row for compiler/packer attribution'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag for persisted static-analysis artifacts'),
})

export const CompilerPackerDetectDataSchema = z.object({
  status: z.enum(['ready', 'setup_required']),
  sample_id: z.string(),
  compiler_findings: z.array(AttributionFindingSchema),
  packer_findings: z.array(AttributionFindingSchema),
  protector_findings: z.array(AttributionFindingSchema),
  file_type_findings: z.array(AttributionFindingSchema),
  summary: z.object({
    compiler_count: z.number().int().nonnegative(),
    packer_count: z.number().int().nonnegative(),
    protector_count: z.number().int().nonnegative(),
    file_type_count: z.number().int().nonnegative(),
    likely_primary_file_type: z.string().nullable(),
  }),
  backend: BackendSchema,
  confidence_semantics: ConfidenceSemanticsSchema.nullable(),
  analysis_id: z.string().optional(),
  artifact: z
    .object({
      id: z.string(),
      type: z.string(),
      path: z.string(),
      sha256: z.string(),
      mime: z.string().optional(),
    })
    .optional(),
  raw_backend: z.any().nullable().optional(),
})

export const compilerPackerDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: CompilerPackerDetectDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const compilerPackerDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Identify likely compiler, packer, protector, and file-type signatures with a Detect It Easy-style backend and normalized MCP output.',
  inputSchema: compilerPackerDetectInputSchema,
  outputSchema: compilerPackerDetectOutputSchema,
}

interface DieExecutionResult {
  stdout: string
  stderr: string
  format: 'json' | 'text'
  command: string[]
}

interface CompilerPackerDetectDependencies {
  resolveBackend?: () => ExternalExecutableResolution
  executeBackend?: (binaryPath: string, samplePath: string, timeoutSec: number) => Promise<DieExecutionResult>
}

function detectCategory(text: string): 'compiler' | 'packer' | 'protector' | 'file_type' | 'unknown' {
  const lowered = text.toLowerCase()
  if (/(compiler|visual c\+\+|msvc|borland|gcc|clang|delphi|rust|go build)/.test(lowered)) return 'compiler'
  if (/(packer|upx|aspack|mpress|petite|themida|vmprotect|fsg)/.test(lowered)) return 'packer'
  if (/(protector|obfuscator|virtualizer|sig)/.test(lowered)) return 'protector'
  if (/(pe32|pe32\+|elf|mach-o|ms-dos|file type|library|exe|dll)/.test(lowered)) return 'file_type'
  return 'unknown'
}

function buildFinding(
  name: string,
  category: z.infer<typeof AttributionFindingSchema>['category'],
  source: string,
  evidenceSummary?: string
) {
  const confidence =
    category === 'compiler' || category === 'packer' || category === 'protector'
      ? 0.78
      : category === 'file_type'
        ? 0.72
        : 0.46
  return {
    name,
    category,
    confidence,
    evidence_summary: evidenceSummary || `${source}: ${name}`,
    source,
  }
}

function normalizeJsonFindings(raw: unknown): z.infer<typeof AttributionFindingSchema>[] {
  const findings: z.infer<typeof AttributionFindingSchema>[] = []
  const visit = (value: unknown, source = 'die-json') => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item, source)
      return
    }
    if (!value || typeof value !== 'object') {
      if (typeof value === 'string' && value.trim()) {
        findings.push(buildFinding(value.trim(), detectCategory(value), source))
      }
      return
    }
    const record = value as Record<string, unknown>
    const nameCandidate = ['name', 'type', 'value', 'string', 'title', 'description']
      .map((key) => record[key])
      .find((item) => typeof item === 'string' && item.trim().length > 0)
    if (typeof nameCandidate === 'string') {
      const categoryCandidate = ['category', 'kind', 'class', 'type']
        .map((key) => record[key])
        .find((item) => typeof item === 'string' && item.trim().length > 0)
      const category =
        typeof categoryCandidate === 'string'
          ? detectCategory(`${categoryCandidate} ${nameCandidate}`)
          : detectCategory(nameCandidate)
      findings.push(
        buildFinding(
          nameCandidate.trim(),
          category,
          source,
          Object.entries(record)
            .slice(0, 4)
            .map(([key, item]) => `${key}=${String(item)}`)
            .join(', ')
        )
      )
    }
    for (const nested of Object.values(record)) {
      if (typeof nested === 'object') visit(nested, source)
    }
  }
  visit(raw)
  return findings
}

function normalizeTextFindings(stdout: string, stderr: string): z.infer<typeof AttributionFindingSchema>[] {
  const findings: z.infer<typeof AttributionFindingSchema>[] = []
  const lines = `${stdout}\n${stderr}`
    .split(/\r?\n/)
    .map((item) => item.replace(/\0/g, '').trim())
    .filter((item) => item.length > 0)
  for (const line of lines) {
    const normalizedLine = line.replace(/^\[[^\]]+\]\s*/, '')
    const parts = normalizedLine.split(/\s*:\s*/, 2)
    const payload = parts.length === 2 ? parts[1] : normalizedLine
    if (!payload.trim()) continue
    findings.push(buildFinding(payload.trim(), detectCategory(parts[0] || normalizedLine), 'die-text', normalizedLine))
  }
  return findings
}

function parseLooseJsonOutput(stdout: string): unknown | null {
  const trimmed = stdout.trim()
  if (!trimmed) {
    return null
  }

  const candidates = new Set<string>()
  candidates.add(trimmed)

  const lines = trimmed.split(/\r?\n/)
  const jsonStartIndex = lines.findIndex((line) => {
    const normalized = line.trim()
    return /^(?:\{|\[(?!\!))/.test(normalized)
  })
  if (jsonStartIndex >= 0) {
    candidates.add(lines.slice(jsonStartIndex).join('\n').trim())
  }

  const objectStart = trimmed.indexOf('{')
  const objectEnd = trimmed.lastIndexOf('}')
  if (objectStart >= 0 && objectEnd > objectStart) {
    candidates.add(trimmed.slice(objectStart, objectEnd + 1).trim())
  }

  const arrayStart = trimmed.search(/\[(?!\!)/)
  const arrayEnd = trimmed.lastIndexOf(']')
  if (arrayStart >= 0 && arrayEnd > arrayStart) {
    candidates.add(trimmed.slice(arrayStart, arrayEnd + 1).trim())
  }

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate)
    } catch {
      // Try the next candidate.
    }
  }

  return null
}

function partitionFindings(findings: z.infer<typeof AttributionFindingSchema>[]) {
  const pick = (category: z.infer<typeof AttributionFindingSchema>['category']) =>
    findings.filter((item) => item.category === category)
  return {
    compiler_findings: pick('compiler'),
    packer_findings: pick('packer'),
    protector_findings: pick('protector'),
    file_type_findings: pick('file_type'),
  }
}

async function defaultExecuteBackend(
  binaryPath: string,
  samplePath: string,
  timeoutSec: number
): Promise<DieExecutionResult> {
  const attempts: Array<{ args: string[]; format: 'json' | 'text' }> = [
    { args: ['-j', samplePath], format: 'json' },
    { args: ['--json', samplePath], format: 'json' },
    { args: [samplePath], format: 'text' },
  ]

  let lastStdout = ''
  let lastStderr = ''
  for (const attempt of attempts) {
    try {
      const result = await execFileAsync(binaryPath, attempt.args, {
        timeout: Math.max(5000, timeoutSec * 1000),
        windowsHide: true,
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
      })
      return { stdout: result.stdout || '', stderr: result.stderr || '', format: attempt.format, command: [binaryPath, ...attempt.args] }
    } catch (error) {
      const failed = error as { stdout?: string; stderr?: string }
      lastStdout = typeof failed.stdout === 'string' ? failed.stdout : ''
      lastStderr = typeof failed.stderr === 'string' ? failed.stderr : String(error)
      if (attempt.format === 'text') break
    }
  }

  throw new Error(`Detect It Easy execution failed: ${(lastStderr || lastStdout || 'unknown error').trim()}`)
}

export function createCompilerPackerDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: CompilerPackerDetectDependencies = {}
) {
  const resolveBackend = dependencies.resolveBackend || (() => resolveDieCli())
  const executeBackend = dependencies.executeBackend || defaultExecuteBackend

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = compilerPackerDetectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const backend = resolveBackend()
      if (!backend.available || !backend.path) {
        return {
          ok: true,
          data: {
            status: 'setup_required',
            sample_id: input.sample_id,
            compiler_findings: [],
            packer_findings: [],
            protector_findings: [],
            file_type_findings: [],
            summary: {
              compiler_count: 0,
              packer_count: 0,
              protector_count: 0,
              file_type_count: 0,
              likely_primary_file_type: null,
            },
            backend,
            confidence_semantics: null,
            raw_backend: null,
          },
          warnings: backend.error ? [backend.error] : undefined,
          setup_actions: buildStaticAnalysisSetupActions(),
          required_user_inputs: buildStaticAnalysisRequiredUserInputs(),
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const execution = await executeBackend(backend.path, samplePath, input.timeout_sec)
      const findings =
        execution.format === 'json'
          ? (() => {
              const parsed = parseLooseJsonOutput(execution.stdout)
              if (parsed !== null) {
                return normalizeJsonFindings(parsed)
              }
              warnings.push(
                'Detect It Easy emitted non-JSON output while JSON mode was requested; fell back to text normalization.'
              )
              return normalizeTextFindings(execution.stdout, execution.stderr)
            })()
          : normalizeTextFindings(execution.stdout, execution.stderr)
      const deduped = new Map<string, z.infer<typeof AttributionFindingSchema>>()
      for (const finding of findings) {
        const key = `${finding.category}:${finding.name.toLowerCase()}`
        if (!deduped.has(key)) deduped.set(key, finding)
      }
      const normalizedFindings = Array.from(deduped.values())
      const partitioned = partitionFindings(normalizedFindings)
      const summary = {
        compiler_count: partitioned.compiler_findings.length,
        packer_count: partitioned.packer_findings.length,
        protector_count: partitioned.protector_findings.length,
        file_type_count: partitioned.file_type_findings.length,
        likely_primary_file_type: partitioned.file_type_findings[0]?.name || null,
      }
      const confidenceSemantics = buildToolchainConfidenceSemantics({
        score: Math.min(
          0.97,
          0.36 +
            Math.min(0.2, summary.compiler_count * 0.18) +
            Math.min(0.2, summary.packer_count * 0.18) +
            Math.min(0.16, summary.protector_count * 0.16) +
            (summary.file_type_count > 0 ? 0.08 : 0)
        ),
        compilerCount: summary.compiler_count,
        packerCount: summary.packer_count,
        protectorCount: summary.protector_count,
        backendSource: backend.source,
      })

      let artifact
      const artifacts = []
      if (input.persist_artifact) {
        const artifactPayload = {
          session_tag: input.session_tag || null,
          sample_id: input.sample_id,
          status: 'ready',
          ...partitioned,
          summary,
          backend,
          confidence_semantics: confidenceSemantics,
          raw_backend: {
            format: execution.format,
            command: execution.command,
            stdout: execution.stdout,
            stderr: execution.stderr,
          },
          created_at: new Date().toISOString(),
        }
        artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
          'compiler_packer',
          artifactPayload,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'compiler_packer_detection',
          backend: 'die',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            summary,
            artifact_id: artifact?.id || null,
            backend_source: backend.source,
          }),
          metrics_json: JSON.stringify(summary),
        })
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          ...partitioned,
          summary,
          backend,
          confidence_semantics: confidenceSemantics,
          analysis_id: analysisId,
          artifact,
          raw_backend: {
            format: execution.format,
            command: execution.command,
            stdout: execution.stdout,
            stderr: execution.stderr,
          },
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
