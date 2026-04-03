/**
 * frida.trace.capture tool
 * Capture and normalize Frida traces with canonical schema and filtering.
 */

import { spawn } from 'child_process'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'frida.trace.capture'
const TOOL_VERSION = '0.1.0'

export const FridaTraceCaptureInputSchema = z.object({
  sample_id: z.string().optional().describe('Sample ID for trace capture'),
  session_id: z.string().optional().describe('Existing Frida session ID to capture from'),
  artifact_id: z.string().optional().describe('Artifact ID of previously captured trace'),
  trace_format: z
    .enum(['normalized', 'raw', 'compact'])
    .optional()
    .default('normalized')
    .describe('Output format for captured trace'),
  filter: z
    .object({
      types: z.array(z.string()).optional().describe('Filter by message types'),
      modules: z.array(z.string()).optional().describe('Filter by module names'),
      functions: z.array(z.string()).optional().describe('Filter by function names'),
      min_timestamp: z.number().optional().describe('Minimum timestamp'),
      max_timestamp: z.number().optional().describe('Maximum timestamp'),
    })
    .optional()
    .describe('Trace filtering options'),
  aggregate: z
    .boolean()
    .optional()
    .default(false)
    .describe('Aggregate duplicate events'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(10000)
    .optional()
    .default(1000)
    .describe('Maximum number of trace events to return'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist captured trace as artifact'),
  register_analysis: z
    .boolean()
    .optional()
    .default(true)
    .describe('Register analysis record in database'),
})

export type FridaTraceCaptureInput = z.infer<typeof FridaTraceCaptureInputSchema>

// Canonical trace event schema
export const FridaTraceEventSchema = z.object({
  type: z.string(),
  function: z.string().optional(),
  module: z.string().optional(),
  args: z.array(z.any()).optional(),
  value: z.string().optional(),
  data_preview: z.string().optional(),
  timestamp: z.number().optional(),
  thread_id: z.number().optional(),
  source: z.string().optional(),
  category: z.string().optional(),
})

export type FridaTraceEvent = z.infer<typeof FridaTraceEventSchema>

export const FridaTraceCaptureOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['completed', 'failed', 'timeout', 'error']).optional(),
      session_id: z.string().optional(),
      sample_id: z.string().optional(),
      captured_at: z.string(),
      trace_format: z.string(),
      total_events: z.number(),
      filtered_events: z.number(),
      events: z.array(FridaTraceEventSchema),
      aggregation: z
        .object({
          by_type: z.record(z.number()),
          by_module: z.record(z.number()),
          by_function: z.record(z.number()),
        })
        .optional(),
      warnings: z.array(z.string()),
      errors: z.array(z.string()),
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

export type FridaTraceCaptureOutput = z.infer<typeof FridaTraceCaptureOutputSchema>

export const fridaTraceCaptureToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Capture and normalize Frida traces with canonical schema, filtering, and aggregation.',
  inputSchema: FridaTraceCaptureInputSchema,
  outputSchema: FridaTraceCaptureOutputSchema,
}

interface WorkerRequest {
  job_id: string
  tool: string
  sample: {
    sample_id: string
    path: string
  }
  args: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: {
      allow_dynamic: boolean
      allow_network: boolean
    }
    versions: Record<string, string>
  }
}

interface WorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

interface FridaTraceCaptureDependencies {
  callWorker?: (request: WorkerRequest) => Promise<WorkerResponse>
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

/**
 * Normalize a raw Frida trace event to canonical schema
 */
export function normalizeTraceEvent(event: Record<string, any>): FridaTraceEvent {
  const normalized: FridaTraceEvent = {
    type: event.type || event._type || 'unknown',
  }

  // Preserve standard fields
  if (event.function) normalized.function = event.function
  if (event.module) normalized.module = event.module
  if (event.args) normalized.args = event.args
  if (event.value) normalized.value = event.value
  if (event.data_preview) normalized.data_preview = event.data_preview
  if (event.timestamp) normalized.timestamp = event.timestamp
  if (event.thread_id) normalized.thread_id = event.thread_id
  if (event.source) normalized.source = event.source
  if (event.category) normalized.category = event.category

  // Handle timestamp from _timestamp field
  if (!normalized.timestamp && event._timestamp) {
    normalized.timestamp = event._timestamp
  }

  return normalized
}

/**
 * Filter trace events based on filter criteria
 */
export function filterTraceEvents(
  events: FridaTraceEvent[],
  filter: NonNullable<z.infer<typeof FridaTraceCaptureInputSchema>['filter']>
): FridaTraceEvent[] {
  return events.filter((event) => {
    if (filter.types && filter.types.length > 0) {
      if (!filter.types.includes(event.type)) return false
    }
    if (filter.modules && filter.modules.length > 0) {
      if (!event.module || !filter.modules.some((m) => event.module!.includes(m))) return false
    }
    if (filter.functions && filter.functions.length > 0) {
      if (!event.function || !filter.functions.some((f) => event.function!.includes(f)))
        return false
    }
    if (filter.min_timestamp && event.timestamp && event.timestamp < filter.min_timestamp)
      return false
    if (filter.max_timestamp && event.timestamp && event.timestamp > filter.max_timestamp)
      return false
    return true
  })
}

/**
 * Aggregate trace events by type, module, and function
 */
export function aggregateTraceEvents(events: FridaTraceEvent[]): {
  by_type: Record<string, number>
  by_module: Record<string, number>
  by_function: Record<string, number>
} {
  const aggregation = {
    by_type: {} as Record<string, number>,
    by_module: {} as Record<string, number>,
    by_function: {} as Record<string, number>,
  }

  for (const event of events) {
    // By type
    aggregation.by_type[event.type] = (aggregation.by_type[event.type] || 0) + 1

    // By module
    if (event.module) {
      aggregation.by_module[event.module] = (aggregation.by_module[event.module] || 0) + 1
    }

    // By function
    if (event.function) {
      aggregation.by_function[event.function] = (aggregation.by_function[event.function] || 0) + 1
    }
  }

  return aggregation
}

/**
 * Deduplicate trace events while preserving order
 */
export function deduplicateTraceEvents(events: FridaTraceEvent[]): FridaTraceEvent[] {
  const seen = new Set<string>()
  const deduped: FridaTraceEvent[] = []

  for (const event of events) {
    const key = JSON.stringify({
      type: event.type,
      function: event.function,
      module: event.module,
      args: event.args,
      value: event.value,
    })

    if (!seen.has(key)) {
      seen.add(key)
      deduped.push(event)
    }
  }

  return deduped
}

/**
 * Convert trace events to compact format (summary only)
 */
export function convertToCompactFormat(
  events: FridaTraceEvent[],
  aggregation: ReturnType<typeof aggregateTraceEvents>
): FridaTraceEvent[] {
  // Return only unique type/module/function combinations with counts
  const summary: FridaTraceEvent[] = []
  const seen = new Set<string>()

  for (const event of events) {
    const key = `${event.type}|${event.module || ''}|${event.function || ''}`
    if (!seen.has(key)) {
      seen.add(key)
      summary.push({
        ...event,
        data_preview: `count: ${aggregation.by_type[event.type] || 1}`,
      })
    }
  }

  return summary
}

export function createFridaTraceCaptureHandler(
  deps: PluginToolDeps,
  dependencies?: FridaTraceCaptureDependencies
) {
  const { workspaceManager, database, resolvePackagePath } = deps

  async function callFridaWorker(request: WorkerRequest): Promise<WorkerResponse> {
    return new Promise((resolve, reject) => {
      const workerPath = resolvePackagePath!('workers', 'frida_worker.py')
      const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
      const pythonProcess = spawn(pythonCommand, [workerPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
      })

      let stdout = ''
      let stderr = ''
      let settled = false

      const onDone = (fn: () => void) => {
        if (settled) {
          return
        }
        settled = true
        fn()
      }

      const timer = setTimeout(() => {
        onDone(() => {
          pythonProcess.kill()
          reject(new Error(`Frida worker timed out after 60s`))
        })
      }, 60000)

      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString()
      })

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString()
      })

      pythonProcess.on('error', (error) => {
        onDone(() => {
          clearTimeout(timer)
          reject(new Error(`Failed to spawn Frida worker: ${error.message}`))
        })
      })

      pythonProcess.on('close', (code) => {
        onDone(() => {
          clearTimeout(timer)
          if (code !== 0) {
            reject(new Error(`Frida worker exited with code ${code}. stderr: ${stderr}`))
            return
          }

          try {
            const lines = stdout.trim().split('\n')
            const lastLine = lines[lines.length - 1]
            const response: WorkerResponse = JSON.parse(lastLine)
            resolve(response)
          } catch (error) {
            reject(
              new Error(
                `Failed to parse Frida worker response: ${normalizeError(error)}. stdout: ${stdout}`
              )
            )
          }
        })
      })

      try {
        pythonProcess.stdin.write(JSON.stringify(request) + '\n')
        pythonProcess.stdin.end()
      } catch (error) {
        onDone(() => {
          clearTimeout(timer)
          reject(new Error(`Failed to write to Frida worker: ${normalizeError(error)}`))
        })
      }
    })
  }

  function buildFridaUnavailableResponse(
    input: FridaTraceCaptureInput,
    startTime: number,
    errorMessage: string
  ): WorkerResult {
    return {
      ok: true,
      data: {
        status: 'error',
        session_id: input.session_id,
        sample_id: input.sample_id || 'unknown',
        captured_at: new Date().toISOString(),
        trace_format: input.trace_format,
        total_events: 0,
        filtered_events: 0,
        events: [],
        warnings: [`Frida is not available: ${errorMessage}`],
        errors: [errorMessage],
      },
      warnings: [`Frida is not available: ${errorMessage}`],
      metrics: {
        elapsed_ms: Date.now() - startTime,
        tool: TOOL_NAME,
      },
    }
  }

  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const startTime = Date.now()
    const runWorker = dependencies?.callWorker || callFridaWorker

    try {
      const input = FridaTraceCaptureInputSchema.parse(args)
      const warnings: string[] = []
      const errors: string[] = []

      // Get sample context
      let sampleContext = {
        sample_id: input.sample_id || 'unknown',
        path: '',
      }

      if (input.sample_id) {
        const sample = database.findSample(input.sample_id)
        if (sample) {
          try {
            const workspace = await workspaceManager.getWorkspace(input.sample_id)
            const fs = await import('fs/promises')
            const files = await fs.readdir(workspace.original)
            if (files.length > 0) {
              sampleContext.path = files[0]
            }
          } catch {
            // Ignore errors reading sample context - worker can still run
          }
        }
      }

      // Get traces from worker
      const workerRequest: WorkerRequest = {
        job_id: randomUUID(),
        tool: 'frida.trace.capture',
        sample: sampleContext,
        args: {
          session_id: input.session_id,
          artifact_id: input.artifact_id,
        },
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: true,
            allow_network: false,
          },
          versions: {
            tool_version: TOOL_VERSION,
          },
        },
      }

      let workerResponse: WorkerResponse
      try {
        workerResponse = await runWorker(workerRequest)
      } catch (error) {
        const errorStr = normalizeError(error)
        if (errorStr.includes('Frida is not installed') || errorStr.includes('ModuleNotFoundError')) {
          return buildFridaUnavailableResponse(
            input,
            startTime,
            'Frida runtime not installed. Run: pip install frida'
          )
        }
        return {
          ok: false,
          errors: [errorStr],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (!workerResponse.ok) {
        const errorMsg = workerResponse.errors.join('; ') || 'Frida trace capture failed'
        if (errorMsg.toLowerCase().includes('not installed') || errorMsg.toLowerCase().includes('import')) {
          return buildFridaUnavailableResponse(input, startTime, errorMsg)
        }
        return {
          ok: false,
          errors: [errorMsg],
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      // Process trace data
      const rawData = (workerResponse.data || {}) as Record<string, any>
      const rawTraces = Array.isArray(rawData.traces)
        ? rawData.traces
        : Array.isArray(rawData.events)
          ? rawData.events
          : []

      // Normalize traces
      const normalizedTraces = rawTraces.map(normalizeTraceEvent)
      const totalEvents =
        typeof rawData.total_events === 'number' ? rawData.total_events : normalizedTraces.length

      // Filter traces
      let filteredTraces = normalizedTraces
      if (input.filter) {
        filteredTraces = filterTraceEvents(normalizedTraces, input.filter)
      }

      // Deduplicate if aggregate requested
      if (input.aggregate) {
        filteredTraces = deduplicateTraceEvents(filteredTraces)
      }

      // Apply limit
      if (filteredTraces.length > input.limit) {
        filteredTraces = filteredTraces.slice(0, input.limit)
        warnings.push(`Trace limited to ${input.limit} events from ${filteredTraces.length}`)
      }

      // Compute aggregation
      const aggregation = aggregateTraceEvents(filteredTraces)

      // Convert format if needed
      let finalTraces = filteredTraces
      if (input.trace_format === 'compact') {
        finalTraces = convertToCompactFormat(filteredTraces, aggregation)
      }

      // Build artifact
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && finalTraces.length > 0) {
        const fs = await import('fs/promises')
        const artifactDir = await workspaceManager.ensureDirectory(
          input.sample_id || 'unknown',
          'dynamic'
        )
        const artifactFilename = `frida_trace_${Date.now()}.json`
        const artifactPath = `${artifactDir}/${artifactFilename}`

        const artifactContent = {
          session_id: rawData.session_id || input.session_id,
          sample_id: input.sample_id || 'unknown',
          captured_at: new Date().toISOString(),
          trace_format: input.trace_format,
          total_events: totalEvents,
          filtered_events: finalTraces.length,
          filter_applied: input.filter || null,
          aggregated: input.aggregate,
          events: finalTraces,
          aggregation: input.aggregate ? aggregation : undefined,
        }

        await fs.writeFile(artifactPath, JSON.stringify(artifactContent, null, 2), 'utf-8')

        const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
        const artifactId = `frida_trace_${sha256(artifactContent.captured_at)}`

        artifacts.push({
          id: artifactId,
          type: 'frida_trace',
          path: artifactPath,
          sha256: sha256(JSON.stringify(artifactContent)),
          mime: 'application/json',
          metadata: {
            session_tag: `frida_trace/${input.sample_id || 'unknown'}/${Date.now()}`,
            captured_at: artifactContent.captured_at,
            total_events: totalEvents,
            filtered_events: finalTraces.length,
            trace_format: input.trace_format,
          },
        })
      }

      return {
        ok: true,
        data: {
          status: 'completed',
          session_id: rawData.session_id || input.session_id,
          sample_id: input.sample_id || 'unknown',
          captured_at: new Date().toISOString(),
          trace_format: input.trace_format,
          total_events: totalEvents,
          filtered_events: finalTraces.length,
          events: finalTraces,
          aggregation: aggregation,
          warnings: [...warnings, ...(rawData.warnings || [])],
          errors: errors,
        },
        warnings: [...warnings, ...(workerResponse.warnings || [])],
        errors: errors,
        artifacts,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
