/**
 * dynamic.trace.attribute MCP tool — attribute dynamic trace API calls back to
 * static analysis functions via address correlation.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dynamic.trace.attribute'

export const DynamicTraceAttributeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  trace_artifact_id: z.string().optional().describe('Specific trace artifact to attribute. Uses latest if omitted.'),
})

export const dynamicTraceAttributeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Attribute dynamic trace events (API calls, memory operations) to static analysis functions. ' +
    'Correlates return addresses in traces with Ghidra function boundaries to produce per-function behavior profiles.',
  inputSchema: DynamicTraceAttributeInputSchema,
}

interface FunctionRange {
  name: string
  address: number
  size: number
  end: number
}

interface TraceEvent {
  api?: string
  return_address?: string
  caller_address?: string
  address?: string
  timestamp?: number
  args?: unknown
}

interface AttributedFunction {
  name: string
  address: string
  api_calls: Array<{ api: string; count: number }>
  total_events: number
  behavior_tags: string[]
}

function addressToNumber(addr: string | number): number {
  if (typeof addr === 'number') return addr
  return parseInt(String(addr).replace(/^0x/i, ''), 16)
}

function findContainingFunction(addr: number, functions: FunctionRange[]): FunctionRange | null {
  for (const fn of functions) {
    if (addr >= fn.address && addr < fn.end) return fn
  }
  return null
}

function inferBehaviorTags(apis: string[]): string[] {
  const tags = new Set<string>()
  const lowerApis = apis.map(a => a.toLowerCase())

  if (lowerApis.some(a => a.includes('createfile') || a.includes('writefile') || a.includes('readfile')))
    tags.add('file_io')
  if (lowerApis.some(a => a.includes('regopen') || a.includes('regset') || a.includes('regquery')))
    tags.add('registry')
  if (lowerApis.some(a => a.includes('socket') || a.includes('connect') || a.includes('send') || a.includes('recv') || a.includes('internet')))
    tags.add('network')
  if (lowerApis.some(a => a.includes('crypt') || a.includes('bcrypt')))
    tags.add('crypto')
  if (lowerApis.some(a => a.includes('virtualalloc') || a.includes('virtualprotect')))
    tags.add('memory_manipulation')
  if (lowerApis.some(a => a.includes('createremotethread') || a.includes('writeprocessmemory')))
    tags.add('injection')
  if (lowerApis.some(a => a.includes('createprocess') || a.includes('shellexecute')))
    tags.add('process_creation')
  if (lowerApis.some(a => a.includes('isdebuggerpresent') || a.includes('ntqueryinformation')))
    tags.add('anti_debug')

  return [...tags]
}

export function createDynamicTraceAttributeHandler(
  deps: PluginToolDeps
) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps
  return async (args: z.infer<typeof DynamicTraceAttributeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (!Array.isArray(evidence)) return { ok: false, errors: ['No analysis evidence found'] }

      // Collect function ranges from static analysis
      const functionRanges: FunctionRange[] = []
      for (const entry of evidence) {
        const family = entry.evidence_family ?? ''
        if (family === 'function_map' || family === 'functions') {
          try {
            const data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
            const fns = data?.functions ?? data?.data?.functions ?? []
            for (const fn of fns) {
              const addr = addressToNumber(fn.address ?? fn.entry ?? '0')
              const size = fn.size ?? 0
              if (addr && size) {
                functionRanges.push({ name: fn.name ?? `FUN_${addr.toString(16)}`, address: addr, size, end: addr + size })
              }
            }
          } catch { /* */ }
        }
      }

      if (functionRanges.length === 0) {
        warnings.push('No function map found. Run ghidra.analyze first for accurate attribution.')
      }

      // Collect trace events
      const traceEvents: TraceEvent[] = []
      for (const entry of evidence) {
        const family = entry.evidence_family ?? ''
        if (family === 'dynamic_trace' || family === 'frida_trace' || family === 'runtime_trace') {
          try {
            const data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
            const events = data?.events ?? data?.data?.events ?? data?.trace ?? data?.data?.trace ?? []
            traceEvents.push(...events)
          } catch { /* */ }
        }
      }

      if (traceEvents.length === 0) {
        return { ok: false, errors: ['No dynamic trace data found. Run frida.trace.capture or dynamic.trace.import first.'] }
      }

      // Attribute events to functions
      const fnApiMap = new Map<string, Map<string, number>>()
      const fnEventCount = new Map<string, number>()
      let unattributed = 0

      for (const event of traceEvents) {
        const callerAddr = event.return_address ?? event.caller_address ?? event.address
        if (!callerAddr) { unattributed++; continue }

        const addr = addressToNumber(callerAddr)
        const fn = findContainingFunction(addr, functionRanges)

        if (fn) {
          const api = event.api ?? 'unknown_event'
          if (!fnApiMap.has(fn.name)) fnApiMap.set(fn.name, new Map())
          const apiMap = fnApiMap.get(fn.name)!
          apiMap.set(api, (apiMap.get(api) ?? 0) + 1)
          fnEventCount.set(fn.name, (fnEventCount.get(fn.name) ?? 0) + 1)
        } else {
          unattributed++
        }
      }

      // Build attributed function profiles
      const attributed: AttributedFunction[] = []
      for (const [fnName, apiMap] of fnApiMap) {
        const apis = [...apiMap.entries()]
          .map(([api, count]) => ({ api, count }))
          .sort((a, b) => b.count - a.count)

        const fnRange = functionRanges.find(f => f.name === fnName)
        attributed.push({
          name: fnName,
          address: fnRange ? `0x${fnRange.address.toString(16)}` : 'unknown',
          api_calls: apis,
          total_events: fnEventCount.get(fnName) ?? 0,
          behavior_tags: inferBehaviorTags(apis.map(a => a.api)),
        })
      }

      attributed.sort((a, b) => b.total_events - a.total_events)

      const resultData = {
        attributed_functions: attributed.length,
        total_trace_events: traceEvents.length,
        attributed_events: traceEvents.length - unattributed,
        unattributed_events: unattributed,
        functions: attributed.slice(0, 50),
        behavior_summary: inferBehaviorTags(
          attributed.flatMap(f => f.api_calls.map(a => a.api))
        ),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact?.(
          workspaceManager, database, args.sample_id,
          'trace_attribution', 'trace-attribute', resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
