import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { execFile, spawn } from 'child_process'
import { promisify } from 'util'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { DatabaseManager, Sample } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildDynamicDependencySetupActions,
  buildHeavyBackendSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'
import {
  resolveAnalysisBackends,
  type ExternalExecutableResolution,
  type ToolchainBackendResolution,
} from '../static-backend-discovery.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import {
  buildEvidenceReuseWarnings,
  findCanonicalEvidence,
  persistCanonicalEvidence,
} from '../analysis-evidence.js'
import {
  buildRizinPreviewCompatibilityKey,
  getRuntimeWorkerPool,
} from '../runtime-worker-pool.js'
import { resolvePackagePath } from '../runtime-paths.js'
import {
  ExplanationConfidenceStateSchema,
  ExplanationSurfaceRoleSchema,
} from '../explanation-graphs.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'

const execFileAsync = promisify(execFile)

const ArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.record(z.any()).optional(),
})

const BackendSchema = z.object({
  available: z.boolean(),
  source: z.string().nullable(),
  path: z.string().nullable(),
  version: z.string().nullable(),
  checked_candidates: z.array(z.string()),
  error: z.string().nullable(),
})

const SharedMetricsSchema = z.object({
  elapsed_ms: z.number(),
  tool: z.string(),
})

type CommandResult = {
  stdout: string
  stderr: string
  exitCode: number
  timedOut: boolean
}

type PythonJsonResult = {
  stdout: string
  stderr: string
  parsed: any
}

interface SharedBackendDependencies {
  resolveBackends?: () => ToolchainBackendResolution
  executeCommand?: (
    binaryPath: string,
    args: string[],
    timeoutMs: number,
    options?: { cwd?: string; env?: NodeJS.ProcessEnv }
  ) => Promise<CommandResult>
  runPythonJson?: (
    pythonPath: string,
    script: string,
    payload: unknown,
    timeoutMs: number,
    options?: { cwd?: string; env?: NodeJS.ProcessEnv }
  ) => Promise<PythonJsonResult>
}

function buildMetrics(startTime: number, tool: string) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool,
  }
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;]*m/g, '')
}

function truncateText(text: string, maxChars: number) {
  if (text.length <= maxChars) {
    return { text, truncated: false }
  }
  return {
    text: `${text.slice(0, maxChars)}\n...[truncated ${text.length - maxChars} chars]`,
    truncated: true,
  }
}

function safeJsonParse<T = unknown>(text: string): T | null {
  try {
    return JSON.parse(text) as T
  } catch {
    return null
  }
}

function ensureSampleExists(database: DatabaseManager, sampleId: string) {
  const sample = database.findSample(sampleId)
  if (!sample) {
    throw new Error(`Sample not found: ${sampleId}`)
  }
  return sample
}

function findBackendPreviewEvidence(
  database: DatabaseManager,
  sample: Pick<Sample, 'id' | 'sha256'>,
  backend: string,
  mode: string,
  args: Record<string, unknown>,
  freshnessMarker?: string | null
) {
  return findCanonicalEvidence(database, {
    sample,
    evidenceFamily: 'backend_preview',
    backend,
    mode,
    args,
    freshnessMarker,
  })
}

function persistBackendPreviewEvidence(
  database: DatabaseManager,
  sample: Pick<Sample, 'id' | 'sha256'>,
  backend: string,
  mode: string,
  args: Record<string, unknown>,
  result: Record<string, unknown>,
  artifactRefs: ArtifactRef[],
  metadata?: Record<string, unknown>,
  freshnessMarker?: string | null
) {
  persistCanonicalEvidence(database, {
    sample,
    evidenceFamily: 'backend_preview',
    backend,
    mode,
    args,
    freshnessMarker,
    result,
    artifactRefs,
    metadata,
    provenance: {
      tool: `${backend}.${mode}`,
      precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
    },
  })
}

function sanitizeSegment(value: string | undefined | null, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

async function persistBackendArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  backend: string,
  operation: string,
  content: string | Buffer,
  options: {
    extension: string
    mime: string
    sessionTag?: string | null
    metadata?: Record<string, unknown>
  }
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizeSegment(options.sessionTag, 'default')
  const outputDir = path.join(workspace.reports, 'backend_tools', sessionSegment, sanitizeSegment(backend, 'backend'))
  await fs.mkdir(outputDir, { recursive: true })

  const fileName = `${sanitizeSegment(operation, 'output')}_${Date.now()}.${options.extension}`
  const absolutePath = path.join(outputDir, fileName)
  await fs.writeFile(absolutePath, content)

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(content).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()
  const artifactType = `backend_${sanitizeSegment(backend, 'backend')}_${sanitizeSegment(operation, 'output')}`

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: options.mime,
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: options.mime,
    ...(options.metadata ? { metadata: options.metadata } : {}),
  }
}

async function executeCommand(
  binaryPath: string,
  args: string[],
  timeoutMs: number,
  options?: { cwd?: string; env?: NodeJS.ProcessEnv }
): Promise<CommandResult> {
  try {
    const result = await execFileAsync(binaryPath, args, {
      encoding: 'utf8',
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      cwd: options?.cwd,
      env: options?.env,
    })
    return {
      stdout: stripAnsi(result.stdout || ''),
      stderr: stripAnsi(result.stderr || ''),
      exitCode: 0,
      timedOut: false,
    }
  } catch (error) {
    const err = error as {
      stdout?: string | Buffer | null
      stderr?: string | Buffer | null
      code?: string | number
      signal?: string
      killed?: boolean
    }
    const stdout =
      typeof err.stdout === 'string'
        ? err.stdout
        : Buffer.isBuffer(err.stdout)
          ? err.stdout.toString('utf8')
          : ''
    const stderr =
      typeof err.stderr === 'string'
        ? err.stderr
        : Buffer.isBuffer(err.stderr)
          ? err.stderr.toString('utf8')
          : ''
    return {
      stdout: stripAnsi(stdout),
      stderr: stripAnsi(stderr),
      exitCode: typeof err.code === 'number' ? err.code : 1,
      timedOut: err.signal === 'SIGTERM' || err.killed === true,
    }
  }
}

async function runPythonJson(
  pythonPath: string,
  script: string,
  payload: unknown,
  timeoutMs: number,
  options?: { cwd?: string; env?: NodeJS.ProcessEnv }
): Promise<PythonJsonResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(pythonPath, ['-c', script], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: options?.cwd,
      env: options?.env,
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false

    const finish = (fn: () => void) => {
      if (settled) {
        return
      }
      settled = true
      fn()
    }

    const timer = setTimeout(() => {
      finish(() => {
        child.kill()
        reject(new Error(`Python backend timed out after ${timeoutMs}ms`))
      })
    }, timeoutMs)

    child.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      finish(() => {
        clearTimeout(timer)
        reject(error)
      })
    })

    child.on('close', (code) => {
      finish(() => {
        clearTimeout(timer)
        if (code !== 0) {
          reject(new Error(`Python backend exited with code ${code}. stderr: ${stderr}`))
          return
        }

        const lines = stdout
          .trim()
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
        const lastLine = lines[lines.length - 1]
        if (!lastLine) {
          reject(new Error(`Python backend produced no JSON output. stderr: ${stderr}`))
          return
        }

        try {
          resolve({
            stdout,
            stderr,
            parsed: JSON.parse(lastLine),
          })
        } catch (error) {
          reject(
            new Error(
              `Failed to parse Python backend JSON output: ${normalizeError(error)}. stdout: ${stdout}`
            )
          )
        }
      })
    })

    child.stdin.write(JSON.stringify(payload))
    child.stdin.end()
  })
}

function buildStaticSetupRequired(
  backend: ExternalExecutableResolution,
  startTime: number,
  toolName: string
): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'setup_required',
      backend,
      summary: backend.error || 'Backend is unavailable.',
      recommended_next_tools: ['system.health', 'system.setup.guide', 'tool.help'],
      next_actions: [
        'Inspect setup_actions and configure the missing backend path or package.',
        'Retry the same backend-specific MCP tool after the backend becomes available.',
      ],
    },
    warnings: [backend.error || 'Backend unavailable'],
    setup_actions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildHeavyBackendSetupActions()
    ),
    metrics: buildMetrics(startTime, toolName),
  }
}

function buildDynamicSetupRequired(
  backend: ExternalExecutableResolution,
  startTime: number,
  toolName: string
): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'setup_required',
      backend,
      summary: backend.error || 'Backend is unavailable.',
      recommended_next_tools: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
      next_actions: [
        'Review dynamic dependency readiness and any missing rootfs or interpreter configuration.',
        'Retry this backend-specific tool after the runtime becomes available.',
      ],
    },
    warnings: [backend.error || 'Backend unavailable'],
    setup_actions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildDynamicDependencySetupActions()
    ),
    required_user_inputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
    metrics: buildMetrics(startTime, toolName),
  }
}

async function resolveSampleFile(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string
): Promise<string> {
  ensureSampleExists(database, sampleId)
  const { samplePath } = await resolvePrimarySamplePath(workspaceManager, sampleId)
  return samplePath
}

export const graphvizRenderInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>) used for artifact persistence.'),
  graph_text: z.string().min(1).describe('DOT graph source to render.'),
  format: z.enum(['svg', 'png']).default('svg').describe('Rendered output format.'),
  layout: z
    .enum(['dot', 'neato', 'fdp', 'sfdp', 'circo', 'twopi'])
    .default('dot')
    .describe('Graphviz layout engine.'),
  timeout_sec: z.number().int().min(1).max(120).default(30).describe('Renderer timeout in seconds.'),
  preview_max_chars: z
    .number()
    .int()
    .min(128)
    .max(4000)
    .default(1000)
    .describe('Maximum inline preview characters from the rendered asset text when the format is svg.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the rendered output as an artifact in reports/backend_tools.'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional artifact session tag for grouping graphviz outputs.'),
})

export const graphvizRenderOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      graph_semantics: z
        .object({
          surface_role: ExplanationSurfaceRoleSchema,
          confidence_state: ExplanationConfidenceStateSchema,
          upstream_surface: z.string(),
          omissions: z.array(z.object({ code: z.string(), reason: z.string() })).optional(),
        })
        .optional(),
      format: z.enum(['svg', 'png']).optional(),
      layout: z.string().optional(),
      preview: z
        .object({
          inline_text: z.string().optional(),
          truncated: z.boolean(),
          char_count: z.number().int().nonnegative(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const graphvizRenderToolDefinition: ToolDefinition = {
  name: 'graphviz.render',
  description:
    'Render DOT graph text with Graphviz into SVG or PNG artifacts. This is a renderer/export helper over an existing graph, not the primary analysis or explanation surface. Use it when you explicitly want Graphviz output beyond code.function.cfg and need artifact-first graph rendering.',
  inputSchema: graphvizRenderInputSchema,
  outputSchema: graphvizRenderOutputSchema,
}

export function createGraphvizRenderHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = graphvizRenderInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.graphviz
      if (!backend.available || !backend.path) {
        return {
          ok: true,
          data: {
            status: 'setup_required',
            backend,
            sample_id: input.sample_id,
            tool_surface_role: 'renderer_helper',
            preferred_primary_tools: ['code.function.cfg', 'workflow.summarize', 'report.summarize'],
            graph_semantics: {
              surface_role: 'render_export_helper',
              confidence_state: 'observed',
              upstream_surface: 'code.function.cfg',
              omissions: [
                {
                  code: 'renderer_unavailable',
                  reason:
                    'Graphviz is unavailable, so only upstream text graph exports can currently carry semantics.',
                },
              ],
            },
            summary: backend.error || 'Graphviz renderer is unavailable.',
            recommended_next_tools: ['code.function.cfg', 'system.health', 'system.setup.guide'],
            next_actions: [
              'Use code.function.cfg for the primary graph semantics and artifact-first text exports.',
              'Install Graphviz before retrying this render/export helper.',
            ],
          },
          warnings: [backend.error || 'Backend unavailable'],
          setup_actions: mergeSetupActions(
            buildCoreLinuxToolchainSetupActions(),
            buildHeavyBackendSetupActions()
          ),
          metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
        }
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'graphviz-render-'))
      const inputPath = path.join(tempDir, 'graph.dot')
      const outputPath = path.join(tempDir, `rendered.${input.format}`)
      await fs.writeFile(inputPath, input.graph_text, 'utf8')

      const commandResult = await runner(
        backend.path,
        [`-K${input.layout}`, `-T${input.format}`, inputPath, '-o', outputPath],
        input.timeout_sec * 1000
      )

      if (commandResult.exitCode !== 0) {
        await fs.rm(tempDir, { recursive: true, force: true })
        return {
          ok: false,
          errors: [
            `Graphviz render failed with exit code ${commandResult.exitCode}`,
            commandResult.stderr || commandResult.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
        }
      }

      const rendered = await fs.readFile(outputPath)
      const previewSource = input.format === 'svg' ? rendered.toString('utf8') : ''
      const preview = truncateText(previewSource, input.preview_max_chars)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'graphviz',
          `render_${input.format}`,
          rendered,
          {
            extension: input.format,
            mime: input.format === 'svg' ? 'image/svg+xml' : 'image/png',
            sessionTag: input.session_tag,
            metadata: {
              layout: input.layout,
            },
          }
        )
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          tool_surface_role: 'renderer_helper',
          preferred_primary_tools: ['code.function.cfg', 'workflow.summarize', 'report.summarize'],
          graph_semantics: {
            surface_role: 'render_export_helper',
            confidence_state: 'observed',
            upstream_surface: 'code.function.cfg',
            omissions: [
              {
                code: 'render_only',
                reason:
                  'graphviz.render only converts an existing DOT graph into SVG or PNG. It does not add deeper analysis semantics on its own.',
              },
            ],
          },
          format: input.format,
          layout: input.layout,
          preview: {
            inline_text: input.format === 'svg' ? preview.text : undefined,
            truncated: preview.truncated,
            char_count: previewSource.length,
          },
          artifact,
          summary: `Rendered DOT input with Graphviz ${backend.version || 'unknown version'} using layout=${input.layout} to ${input.format}.`,
          recommended_next_tools: ['artifact.read', 'code.function.cfg', 'workflow.summarize'],
          next_actions: artifact
            ? [
                'Read the persisted artifact if you need the full rendered payload or share it downstream.',
                'Return to code.function.cfg or workflow.summarize when you need the graph semantics, not just the rendered asset.',
              ]
            : ['Enable persist_artifact to keep the rendered output under reports/backend_tools.'],
        },
        artifacts,
        metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
      }
    }
  }
}

export const rizinAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['info', 'sections', 'imports', 'exports', 'entrypoints', 'functions', 'strings'])
    .default('info')
    .describe('Bounded Rizin inspection mode.'),
  max_items: z.number().int().min(1).max(200).default(25).describe('Maximum preview items to return.'),
  timeout_sec: z.number().int().min(1).max(180).default(45).describe('Rizin execution timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist the raw JSON result as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const rizinAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      item_count: z.number().int().nonnegative().optional(),
      preview: z.any().optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const rizinAnalyzeToolDefinition: ToolDefinition = {
  name: 'rizin.analyze',
  description:
    'Run bounded Rizin inspection on a sample for info, sections, imports, exports, entrypoints, functions, or strings. Use this when you explicitly want Rizin-backed inspection instead of the default workflow backends.',
  inputSchema: rizinAnalyzeInputSchema,
  outputSchema: rizinAnalyzeOutputSchema,
}

function getRizinCommand(operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']): string {
  switch (operation) {
    case 'sections':
      return 'iSj'
    case 'imports':
      return 'iij'
    case 'exports':
      return 'iEj'
    case 'entrypoints':
      return 'iej'
    case 'functions':
      return 'aaa;aflj'
    case 'strings':
      return 'izj'
    case 'info':
    default:
      return 'ij'
  }
}

export function createRizinAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = rizinAnalyzeInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
        max_items: input.max_items,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'rizin',
        input.operation,
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.rizin
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, rizinAnalyzeToolDefinition.name)
      }

      const command = getRizinCommand(input.operation)
      const pooledResult = !dependencies?.executeCommand
        ? await getRuntimeWorkerPool().executeHelperWorker(
            {
              job_id: randomUUID(),
              backend_path: backend.path,
              sample_path: samplePath,
              command,
              timeout_ms: input.timeout_sec * 1000,
            },
            {
              database,
              family: 'rizin.preview',
              compatibilityKey: buildRizinPreviewCompatibilityKey({
                backendPath: backend.path,
                backendVersion: backend.version,
                operation: input.operation,
                helperPath: resolvePackagePath('workers', 'rizin_preview_worker.py'),
              }),
              timeoutMs: input.timeout_sec * 1000,
              spawnConfig: {
                command:
                  process.platform === 'win32'
                    ? 'python'
                    : 'python3',
                args: [resolvePackagePath('workers', 'rizin_preview_worker.py')],
              },
            }
          )
        : null
      const commandResult = dependencies?.executeCommand
        ? await dependencies.executeCommand(
            backend.path,
            ['-A', '-q0', '-c', `${command};q`, samplePath],
            input.timeout_sec * 1000
          )
        : null

      const effectiveResult =
        pooledResult
          ? {
              stdout:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).stdout === 'string'
                  ? String((pooledResult.response.data as Record<string, unknown>).stdout)
                  : '',
              stderr:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).stderr === 'string'
                  ? String((pooledResult.response.data as Record<string, unknown>).stderr)
                  : '',
              exitCode:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).exit_code === 'number'
                  ? Number((pooledResult.response.data as Record<string, unknown>).exit_code)
                  : pooledResult.response.ok
                    ? 0
                    : 1,
              timedOut:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).timed_out === 'boolean'
                  ? Boolean((pooledResult.response.data as Record<string, unknown>).timed_out)
                  : false,
            }
          : {
              stdout: commandResult?.stdout || '',
              stderr: commandResult?.stderr || '',
              exitCode: commandResult?.exitCode ?? 1,
              timedOut: commandResult?.timedOut ?? false,
            }

      if (pooledResult && !pooledResult.response.ok) {
        return {
          ok: false,
          errors:
            pooledResult.response.errors && pooledResult.response.errors.length > 0
              ? pooledResult.response.errors
              : ['Rizin pooled helper failed without returning a concrete error.'],
          warnings: pooledResult.response.warnings,
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      if (effectiveResult.exitCode !== 0) {
        return {
          ok: false,
          errors: [
            `Rizin exited with code ${effectiveResult.exitCode}`,
            effectiveResult.stderr || effectiveResult.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const parsed = safeJsonParse<any>(effectiveResult.stdout.trim())
      let preview: unknown = parsed
      let itemCount = 0
      if (Array.isArray(parsed)) {
        itemCount = parsed.length
        preview = parsed.slice(0, input.max_items)
      } else if (parsed && typeof parsed === 'object') {
        const entries = Object.entries(parsed)
        itemCount = entries.length
        preview = Object.fromEntries(entries.slice(0, input.max_items))
      } else {
        const previewText = truncateText(effectiveResult.stdout.trim(), 3000)
        preview = {
          inline_text: previewText.text,
          truncated: previewText.truncated,
        }
      }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'rizin',
          input.operation,
          JSON.stringify(parsed ?? { stdout: commandResult.stdout }, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        operation: input.operation,
        item_count: itemCount,
        preview,
        worker_pool: pooledResult
          ? {
              family: pooledResult.lease.family,
              compatibility_key: pooledResult.lease.compatibility_key,
              deployment_key: pooledResult.lease.deployment_key,
              worker_id: pooledResult.lease.worker_id,
              pool_kind: pooledResult.lease.pool_kind,
              warm_reuse: pooledResult.lease.warm_reuse,
              cold_start: pooledResult.lease.cold_start,
            }
          : undefined,
        artifact,
        summary: `Rizin completed ${input.operation} inspection for ${input.sample_id}.`,
        recommended_next_tools: ['artifact.read', 'code.function.disassemble', 'code.xrefs.analyze'],
        next_actions: [
          'Use artifact.read for the full JSON payload when the inline preview is truncated.',
          'Prefer Ghidra-backed code tools when you need code-level decompile or reconstruction after this quick inspection.',
        ],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'rizin',
        input.operation,
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    }
  }
}

export const yaraXScanInputSchema = z
  .object({
    sample_id: z.string().describe('Target sample identifier.'),
    rules_text: z.string().optional().describe('Inline YARA-X source text.'),
    rules_path: z.string().optional().describe('Absolute path to a YARA or YARA-X rules file.'),
    timeout_sec: z.number().int().min(1).max(180).default(30).describe('YARA-X scan timeout in seconds.'),
    max_matches_per_pattern: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(250)
      .describe('Maximum matches per pattern for the scanner.'),
    persist_artifact: z.boolean().default(true).describe('Persist the JSON scan result as an artifact.'),
    session_tag: z.string().optional().describe('Optional artifact session tag.'),
  })
  .superRefine((data, ctx) => {
    if (!data.rules_text && !data.rules_path) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['rules_text'],
        message: 'Either rules_text or rules_path must be provided',
      })
    }
  })

export const yaraXScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      match_count: z.number().int().nonnegative().optional(),
      matches: z.array(z.any()).optional(),
      module_outputs: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const yaraXScanToolDefinition: ToolDefinition = {
  name: 'yara_x.scan',
  description:
    'Scan a sample with YARA-X using inline rules or a rules file. Use this when you explicitly want the newer YARA-X engine instead of the legacy yara.scan path.',
  inputSchema: yaraXScanInputSchema,
  outputSchema: yaraXScanOutputSchema,
}

const YARAX_SCAN_SCRIPT = `
import json
import pathlib
import sys
import yara_x

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
rules_text = payload.get("rules_text")
rules_path = payload.get("rules_path")
max_matches = int(payload.get("max_matches_per_pattern", 250))
timeout_sec = int(payload.get("timeout_sec", 30))

if not rules_text and rules_path:
    rules_text = pathlib.Path(rules_path).read_text(encoding="utf-8")

rules = yara_x.compile(rules_text)
scanner = yara_x.Scanner(rules)
scanner.set_timeout(timeout_sec)
scanner.max_matches_per_pattern(max_matches)

data = pathlib.Path(sample_path).read_bytes()
results = scanner.scan(data)

matching_rules = []
for rule in getattr(results, "matching_rules", []):
    patterns = []
    for pattern in getattr(rule, "patterns", []):
        matches = []
        for match in getattr(pattern, "matches", []):
            matches.append({
                "offset": int(getattr(match, "offset", 0)),
                "length": int(getattr(match, "length", 0)),
            })
        patterns.append({
            "identifier": getattr(pattern, "identifier", ""),
            "matches": matches,
        })
    matching_rules.append({
        "identifier": getattr(rule, "identifier", ""),
        "namespace": getattr(rule, "namespace", ""),
        "patterns": patterns,
    })

print(json.dumps({
    "match_count": len(matching_rules),
    "matching_rules": matching_rules,
    "module_outputs": getattr(results, "module_outputs", {}) or {},
}, ensure_ascii=False))
`.trim()

export function createYaraXScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = yaraXScanInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      let rulesDigest: string | null = null
      if (input.rules_text) {
        rulesDigest = createHash('sha256').update(input.rules_text).digest('hex')
      } else if (input.rules_path) {
        try {
          const rulesContent = await fs.readFile(input.rules_path, 'utf8')
          rulesDigest = createHash('sha256').update(rulesContent).digest('hex')
        } catch {
          rulesDigest = createHash('sha256').update(input.rules_path).digest('hex')
        }
      }
      const evidenceArgs = {
        rules_digest: rulesDigest,
        max_matches_per_pattern: input.max_matches_per_pattern,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'yara_x',
        'scan',
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.yara_x
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, yaraXScanToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        YARAX_SCAN_SCRIPT,
        {
          sample_path: samplePath,
          rules_text: input.rules_text,
          rules_path: input.rules_path,
          max_matches_per_pattern: input.max_matches_per_pattern,
          timeout_sec: input.timeout_sec,
        },
        input.timeout_sec * 1000 + 5000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'yara_x',
          'scan',
          JSON.stringify(result.parsed, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      const matchingRules = Array.isArray(result.parsed?.matching_rules) ? result.parsed.matching_rules : []
      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        match_count: Number(result.parsed?.match_count || matchingRules.length || 0),
        matches: matchingRules.slice(0, 25),
        module_outputs: result.parsed?.module_outputs || {},
        artifact,
        summary: `YARA-X scanned ${input.sample_id} and produced ${matchingRules.length} matching rule(s).`,
        recommended_next_tools: ['artifact.read', 'yara.scan', 'workflow.analyze.start'],
        next_actions: [
          'Use artifact.read for the full rule match payload when you need all pattern offsets.',
          'Compare with yara.scan if you want legacy-rule behavior, then continue with workflow.analyze.start or workflow.analyze.promote instead of restarting older synchronous facades.',
        ],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'yara_x',
        'scan',
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
          rules_path: input.rules_path || null,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    }
  }
}

export const upxInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['list', 'test', 'decompress'])
    .default('test')
    .describe('UPX list/test/decompress operation.'),
  timeout_sec: z.number().int().min(1).max(180).default(30).describe('UPX timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist decompressed output or inspection text as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const upxInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      exit_code: z.number().int().optional(),
      stdout_preview: z.string().optional(),
      stderr_preview: z.string().optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const upxInspectToolDefinition: ToolDefinition = {
  name: 'upx.inspect',
  description:
    'Inspect or decompress a sample with UPX. Use this when you explicitly want UPX-aware packed-sample checks rather than generic packer heuristics.',
  inputSchema: upxInspectInputSchema,
  outputSchema: upxInspectOutputSchema,
}

export function createUPXInspectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = upxInspectInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.upx
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, upxInspectToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'upx-inspect-'))
      let commandArgs: string[] = []
      let outputPath: string | null = null
      if (input.operation === 'list') {
        commandArgs = ['-l', samplePath]
      } else if (input.operation === 'test') {
        commandArgs = ['-t', samplePath]
      } else {
        outputPath = path.join(tempDir, path.basename(samplePath))
        commandArgs = ['-d', '-o', outputPath, samplePath]
      }

      const commandResult = await runner(
        backend.path,
        commandArgs,
        input.timeout_sec * 1000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        if (input.operation === 'decompress' && outputPath) {
          const decompressed = await fs.readFile(outputPath)
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'upx',
            'decompress',
            decompressed,
            {
              extension: path.extname(samplePath).replace(/^\./, '') || 'bin',
              mime: 'application/octet-stream',
              sessionTag: input.session_tag,
            }
          )
        } else {
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'upx',
            input.operation,
            `${commandResult.stdout}\n${commandResult.stderr}`.trim(),
            {
              extension: 'txt',
              mime: 'text/plain',
              sessionTag: input.session_tag,
            }
          )
        }
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        operation: input.operation,
        exit_code: commandResult.exitCode,
        stdout_preview: truncateText(commandResult.stdout, 2000).text || undefined,
        stderr_preview: truncateText(commandResult.stderr, 2000).text || undefined,
        artifact,
        summary:
          input.operation === 'decompress'
            ? `UPX decompress completed with exit code ${commandResult.exitCode}.`
            : `UPX ${input.operation} completed with exit code ${commandResult.exitCode}.`,
        recommended_next_tools: ['artifact.read', 'packer.detect', 'workflow.analyze.start'],
        next_actions:
          input.operation === 'decompress'
            ? ['Use the persisted artifact as the unpacked binary for secondary analysis, then continue through workflow.analyze.start or workflow.analyze.promote.']
            : ['Inspect stdout/stderr previews or read the artifact for the full UPX output before promoting deeper staged analysis.'],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        warnings:
          commandResult.exitCode !== 0
            ? [`UPX returned non-zero exit code ${commandResult.exitCode}.`]
            : undefined,
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    }
  }
}

export const retdecDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  output_format: z
    .enum(['plain', 'json-human'])
    .default('plain')
    .describe('RetDec output format for the main decompilation file.'),
  timeout_sec: z.number().int().min(10).max(900).default(300).describe('RetDec timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist the generated decompilation output as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const retdecDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      output_format: z.string().optional(),
      preview: z
        .object({
          inline_text: z.string(),
          truncated: z.boolean(),
          char_count: z.number().int().nonnegative(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      supporting_artifacts: z.array(ArtifactRefSchema).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const retdecDecompileToolDefinition: ToolDefinition = {
  name: 'retdec.decompile',
  description:
    'Decompile a sample with RetDec and persist the generated high-level output as an artifact. Use this when you explicitly want a RetDec alternative to the default Ghidra-oriented flow.',
  inputSchema: retdecDecompileInputSchema,
  outputSchema: retdecDecompileOutputSchema,
}

export function createRetDecDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = retdecDecompileInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.retdec
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, retdecDecompileToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'retdec-decompile-'))
      const outputExtension = input.output_format === 'plain' ? 'c' : 'json'
      const outputPath = path.join(tempDir, `retdec_output.${outputExtension}`)
      const result = await runner(
        backend.path,
        ['--cleanup', '--output-format', input.output_format, '--output', outputPath, samplePath],
        input.timeout_sec * 1000
      )

      if (result.exitCode !== 0) {
        await fs.rm(tempDir, { recursive: true, force: true })
        return {
          ok: false,
          errors: [
            `RetDec exited with code ${result.exitCode}`,
            result.stderr || result.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
        }
      }

      const mainOutput = await fs.readFile(outputPath, 'utf8')
      const preview = truncateText(mainOutput, 3000)
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'retdec',
          `decompile_${input.output_format}`,
          mainOutput,
          {
            extension: outputExtension,
            mime: input.output_format === 'plain' ? 'text/x-csrc' : 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          output_format: input.output_format,
          preview: {
            inline_text: preview.text,
            truncated: preview.truncated,
            char_count: mainOutput.length,
          },
          artifact,
          supporting_artifacts: [],
          summary: `RetDec produced ${input.output_format} decompilation output for ${input.sample_id}.`,
          recommended_next_tools: ['artifact.read', 'code.function.decompile', 'workflow.reconstruct'],
          next_actions: [
            'Read the persisted RetDec artifact for the full output before comparing it with Ghidra-backed decompile results.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
      }
    }
  }
}

export const angrAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  analysis: z
    .enum(['cfg_fast'])
    .default('cfg_fast')
    .describe('angr analysis mode. cfg_fast is the bounded default.'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('angr execution timeout in seconds.'),
  max_functions: z.number().int().min(1).max(200).default(25).describe('Maximum function previews to return.'),
  persist_artifact: z.boolean().default(true).describe('Persist the angr summary JSON as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const angrAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      analysis: z.string().optional(),
      arch: z.string().nullable().optional(),
      entry: z.string().nullable().optional(),
      function_count: z.number().int().nonnegative().optional(),
      functions: z.array(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const angrAnalyzeToolDefinition: ToolDefinition = {
  name: 'angr.analyze',
  description:
    'Run bounded angr static analysis against a sample. Use this when you explicitly want angr-backed CFG recovery or function discovery instead of the default Ghidra flow.',
  inputSchema: angrAnalyzeInputSchema,
  outputSchema: angrAnalyzeOutputSchema,
}

const ANGR_CFGFAST_SCRIPT = `
import json
import sys
import angr

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
max_functions = int(payload.get("max_functions", 25))

project = angr.Project(sample_path, load_options={"auto_load_libs": False})
cfg = project.analyses.CFGFast(normalize=True)
functions = []
for addr, func in cfg.kb.functions.items():
    name = getattr(func, "name", None)
    if not name:
        continue
    block_count = len(getattr(func, "block_addrs", []) or [])
    functions.append({
        "address": hex(int(addr)),
        "name": name,
        "block_count": block_count,
        "returning": bool(getattr(func, "returning", False)),
        "unresolved_calls": bool(getattr(func, "has_unresolved_calls", False)),
        "unresolved_jumps": bool(getattr(func, "has_unresolved_jumps", False)),
    })

functions.sort(key=lambda item: (-item["block_count"], item["address"]))
graph = cfg.model.graph
print(json.dumps({
    "arch": str(project.arch),
    "entry": hex(int(project.entry)) if project.entry is not None else None,
    "node_count": len(graph.nodes()),
    "edge_count": len(graph.edges()),
    "function_count": len(functions),
    "functions": functions[:max_functions],
}, ensure_ascii=False))
`.trim()

export function createAngrAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = angrAnalyzeInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.angr
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, angrAnalyzeToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        ANGR_CFGFAST_SCRIPT,
        {
          sample_path: samplePath,
          max_functions: input.max_functions,
        },
        input.timeout_sec * 1000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'angr',
          input.analysis,
          JSON.stringify(result.parsed, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          analysis: input.analysis,
          arch: typeof result.parsed?.arch === 'string' ? result.parsed.arch : null,
          entry: typeof result.parsed?.entry === 'string' ? result.parsed.entry : null,
          function_count: Number(result.parsed?.function_count || 0),
          functions: Array.isArray(result.parsed?.functions) ? result.parsed.functions : [],
          artifact,
          summary: `angr CFGFast recovered ${Number(result.parsed?.function_count || 0)} function(s) for ${input.sample_id}.`,
          recommended_next_tools: ['artifact.read', 'code.functions.smart_recover', 'workflow.function_index_recover'],
          next_actions: [
            'Compare angr-recovered functions with existing Ghidra or pdata-based results when function coverage is weak.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    }
  }
}

export const qilingInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['preflight', 'rootfs_probe'])
    .default('preflight')
    .describe('Qiling readiness inspection mode.'),
  timeout_sec: z.number().int().min(1).max(60).default(20).describe('Backend probe timeout in seconds.'),
})

export const qilingInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      rootfs_configured: z.boolean().optional(),
      rootfs_exists: z.boolean().optional(),
      rootfs_path: z.string().nullable().optional(),
      details: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const qilingInspectToolDefinition: ToolDefinition = {
  name: 'qiling.inspect',
  description:
    'Inspect Qiling readiness, configured rootfs state, and emulation prerequisites for a sample. Use this when you explicitly request Qiling-backed automation or need to verify rootfs prerequisites before emulation.',
  inputSchema: qilingInspectInputSchema,
  outputSchema: qilingInspectOutputSchema,
}

const QILING_INSPECT_SCRIPT = `
import json
import pathlib
import sys
import qiling

payload = json.loads(sys.stdin.read())
rootfs = payload.get("rootfs")
rootfs_exists = bool(rootfs and pathlib.Path(rootfs).exists())
windows_dir = None
kernel32_present = False
if rootfs_exists:
    windows_candidate = pathlib.Path(rootfs) / "Windows" / "System32"
    windows_dir = str(windows_candidate)
    kernel32_present = (windows_candidate / "kernel32.dll").exists()

print(json.dumps({
    "qiling_version": getattr(qiling, "__version__", None),
    "rootfs_configured": bool(rootfs),
    "rootfs_exists": rootfs_exists,
    "rootfs_path": rootfs,
    "system32_path": windows_dir,
    "kernel32_present": kernel32_present,
}, ensure_ascii=False))
`.trim()

export function createQilingInspectHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = qilingInspectInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.qiling
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, qilingInspectToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        QILING_INSPECT_SCRIPT,
        {
          rootfs: process.env.QILING_ROOTFS || null,
        },
        input.timeout_sec * 1000
      )

      const rootfsConfigured = Boolean(result.parsed?.rootfs_configured)
      const rootfsExists = Boolean(result.parsed?.rootfs_exists)
      const warnings: string[] = []
      if (!rootfsConfigured) {
        warnings.push('QILING_ROOTFS is not configured.')
      } else if (!rootfsExists) {
        warnings.push('Configured QILING_ROOTFS does not exist.')
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          operation: input.operation,
          rootfs_configured: rootfsConfigured,
          rootfs_exists: rootfsExists,
          rootfs_path:
            typeof result.parsed?.rootfs_path === 'string' ? result.parsed.rootfs_path : null,
          details: result.parsed,
          summary: rootfsConfigured && rootfsExists
            ? 'Qiling runtime is available and a rootfs is configured.'
            : 'Qiling runtime is available, but the Windows rootfs still needs attention before useful emulation.',
          recommended_next_tools: ['dynamic.dependencies', 'sandbox.execute', 'tool.help'],
          next_actions: rootfsConfigured && rootfsExists
            ? ['Use sandbox.execute or future Qiling-backed workflows when you need controlled emulation.']
            : ['Set QILING_ROOTFS to a mounted Windows rootfs before attempting Qiling-backed emulation.'],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        required_user_inputs: !rootfsConfigured || !rootfsExists
          ? mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs())
          : undefined,
        setup_actions: !rootfsConfigured || !rootfsExists
          ? mergeSetupActions(buildDynamicDependencySetupActions())
          : undefined,
        metrics: buildMetrics(startTime, qilingInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, qilingInspectToolDefinition.name),
      }
    }
  }
}

export const pandaInspectInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample identifier for context; PANDA inspect itself does not execute the sample.'),
  timeout_sec: z.number().int().min(1).max(30).default(15).describe('Backend probe timeout in seconds.'),
})

export const pandaInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().nullable().optional(),
      details: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pandaInspectToolDefinition: ToolDefinition = {
  name: 'panda.inspect',
  description:
    'Inspect PANDA/pandare runtime readiness and record/replay caveats. Use this when you explicitly request PANDA-oriented dynamic analysis support from the MCP server.',
  inputSchema: pandaInspectInputSchema,
  outputSchema: pandaInspectOutputSchema,
}

const PANDA_INSPECT_SCRIPT = `
import json
import sys
import pandare

print(json.dumps({
    "pandare_version": getattr(pandare, "__version__", None),
    "module": "pandare",
    "note": "PANDA support is installed, but full record/replay workflows still require guest images and trace assets.",
}, ensure_ascii=False))
`.trim()

export function createPandaInspectHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pandaInspectInputSchema.parse(args)
      if (input.sample_id) {
        ensureSampleExists(database, input.sample_id)
      }
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.panda
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, pandaInspectToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(backend.path, PANDA_INSPECT_SCRIPT, {}, input.timeout_sec * 1000)

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id || null,
          details: result.parsed,
          summary: 'PANDA bindings are available. Guest images and replay assets are still external prerequisites.',
          recommended_next_tools: ['dynamic.dependencies', 'system.setup.guide', 'tool.help'],
          next_actions: [
            'Prepare guest images and trace assets before expecting full PANDA-backed dynamic workflows.',
          ],
        },
        metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
      }
    }
  }
}

export const wineRunInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  mode: z
    .enum(['preflight', 'run', 'debug'])
    .default('preflight')
    .describe('preflight only checks readiness, run uses wine, debug uses winedbg.'),
  approved: z
    .boolean()
    .default(false)
    .describe('Required when mode=run or mode=debug because those modes attempt to start the sample under Wine.'),
  timeout_sec: z.number().int().min(1).max(180).default(30).describe('Execution timeout in seconds.'),
  arguments: z.array(z.string()).default([]).describe('Optional command-line arguments forwarded to the sample.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist captured stdout/stderr as an artifact for run or debug mode.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const wineRunOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required', 'denied']),
      backend: z.object({
        wine: BackendSchema,
        winedbg: BackendSchema,
      }),
      sample_id: z.string().optional(),
      mode: z.string().optional(),
      approved: z.boolean().optional(),
      execution: z
        .object({
          exit_code: z.number().int(),
          timed_out: z.boolean(),
          stdout_preview: z.string().optional(),
          stderr_preview: z.string().optional(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const wineRunToolDefinition: ToolDefinition = {
  name: 'wine.run',
  description:
    'Preflight or run a sample under Wine or winedbg. Use this only when you explicitly request Linux-hosted Wine debugging or execution; run/debug modes require approved=true.',
  inputSchema: wineRunInputSchema,
  outputSchema: wineRunOutputSchema,
}

export function createWineRunHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = wineRunInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const wineBackend = backends.wine
      const winedbgBackend = backends.winedbg

      const selectedBackend = input.mode === 'debug' ? winedbgBackend : wineBackend
      if (!selectedBackend.available || !selectedBackend.path) {
        return buildDynamicSetupRequired(selectedBackend, startTime, wineRunToolDefinition.name)
      }

      if (input.mode === 'preflight') {
        return {
          ok: true,
          data: {
            status: 'ready',
            backend: {
              wine: wineBackend,
              winedbg: winedbgBackend,
            },
            sample_id: input.sample_id,
            mode: input.mode,
            approved: input.approved,
            summary: 'Wine readiness probe completed without launching the sample.',
            recommended_next_tools: ['sandbox.execute', 'dynamic.dependencies', 'tool.help'],
            next_actions: [
              'Set approved=true only when you intentionally want to launch the sample under Wine or winedbg.',
            ],
          },
          metrics: buildMetrics(startTime, wineRunToolDefinition.name),
        }
      }

      if (!input.approved) {
        return {
          ok: true,
          data: {
            status: 'denied',
            backend: {
              wine: wineBackend,
              winedbg: winedbgBackend,
            },
            sample_id: input.sample_id,
            mode: input.mode,
            approved: false,
            summary: 'Wine execution was not attempted because approved=false.',
            recommended_next_tools: ['sandbox.execute', 'dynamic.dependencies', 'system.health'],
            next_actions: [
              'Retry with approved=true only when you deliberately want MCP to start the sample under Wine or winedbg.',
            ],
          },
          warnings: ['Wine execution requires approved=true.'],
          metrics: buildMetrics(startTime, wineRunToolDefinition.name),
        }
      }

      const runner = dependencies?.executeCommand || executeCommand
      const result = await runner(selectedBackend.path, [samplePath, ...input.arguments], input.timeout_sec * 1000)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          input.mode === 'debug' ? 'winedbg' : 'wine',
          'run',
          `${result.stdout}\n${result.stderr}`.trim(),
          {
            extension: 'txt',
            mime: 'text/plain',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend: {
            wine: wineBackend,
            winedbg: winedbgBackend,
          },
          sample_id: input.sample_id,
          mode: input.mode,
          approved: true,
          execution: {
            exit_code: result.exitCode,
            timed_out: result.timedOut,
            stdout_preview: truncateText(result.stdout, 2000).text || undefined,
            stderr_preview: truncateText(result.stderr, 2000).text || undefined,
          },
          artifact,
          summary: `${input.mode === 'debug' ? 'winedbg' : 'wine'} launched the sample and exited with code ${result.exitCode}.`,
          recommended_next_tools: ['artifact.read', 'sandbox.execute', 'dynamic.trace.import'],
          next_actions: [
            'Use artifact.read for the full Wine stdout/stderr capture when the preview is truncated.',
          ],
        },
        artifacts,
        warnings: result.timedOut ? ['Wine execution timed out before completion.'] : undefined,
        metrics: buildMetrics(startTime, wineRunToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, wineRunToolDefinition.name),
      }
    }
  }
}
