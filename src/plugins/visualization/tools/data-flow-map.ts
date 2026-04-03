/**
 * data.flow.map MCP tool — Track data flow through a binary: how input data
 * is transformed via crypto, encoding, compression, and network operations.
 * Uses evidence from static and dynamic analysis.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'data.flow.map'

export const DataFlowMapInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  focus: z
    .enum(['crypto', 'network', 'file_io', 'all'])
    .optional()
    .default('all')
    .describe('Focus area for data flow tracing'),
})

export const dataFlowMapToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Map data flow through a binary by correlating API call sequences from ' +
    'static imports and dynamic traces. Identifies data transformation chains ' +
    '(read → decrypt → decompress → execute) and data exfiltration paths.',
  inputSchema: DataFlowMapInputSchema,
}

interface FlowNode {
  id: string
  api: string
  category: string
  direction: 'source' | 'transform' | 'sink'
}

interface FlowEdge {
  from: string
  to: string
  label: string
}

const DATA_FLOW_PATTERNS: Array<{
  name: string
  pattern: string[]
  description: string
  severity: string
}> = [
  {
    name: 'file_read_encrypt_send',
    pattern: ['ReadFile', 'CryptEncrypt', 'send'],
    description: 'Data exfiltration: read file → encrypt → send over network',
    severity: 'critical',
  },
  {
    name: 'recv_decrypt_write',
    pattern: ['recv', 'CryptDecrypt', 'WriteFile'],
    description: 'Remote payload: receive data → decrypt → write to disk',
    severity: 'high',
  },
  {
    name: 'recv_alloc_execute',
    pattern: ['recv', 'VirtualAlloc', 'VirtualProtect'],
    description: 'Shellcode execution: receive → allocate memory → make executable',
    severity: 'critical',
  },
  {
    name: 'read_decompress_load',
    pattern: ['ReadFile', 'RtlDecompressBuffer', 'LoadLibrary'],
    description: 'Packed payload: read → decompress → load as module',
    severity: 'high',
  },
  {
    name: 'download_write_execute',
    pattern: ['URLDownloadToFile', 'CreateProcess'],
    description: 'Dropper: download file → execute it',
    severity: 'critical',
  },
  {
    name: 'reg_read_decrypt',
    pattern: ['RegQueryValue', 'CryptDecrypt'],
    description: 'Config from registry: read registry → decrypt config',
    severity: 'medium',
  },
  {
    name: 'resource_load_decrypt_exec',
    pattern: ['FindResource', 'LoadResource', 'CryptDecrypt', 'VirtualAlloc'],
    description: 'Resource-based payload: load embedded resource → decrypt → execute in memory',
    severity: 'high',
  },
]

export function createDataFlowMapHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof DataFlowMapInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Collect APIs from both static and dynamic evidence
      const staticApis: string[] = []
      const dynamicApiSequence: string[] = []

      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const family = entry.evidence_family ?? ''

            // Static imports
            if (family === 'pe_imports' || family === 'elf_imports') {
              const imps = data?.data?.imports ?? data?.imports ?? []
              for (const imp of imps) {
                if (imp.functions) {
                  for (const f of imp.functions as Array<{ name?: string }>) {
                    if (f.name) staticApis.push(f.name)
                  }
                } else if (imp.name || imp.function_name) {
                  staticApis.push(imp.name ?? imp.function_name)
                }
              }
            }

            // Dynamic trace
            if (['dynamic_trace', 'frida_trace', 'sandbox_execution', 'speakeasy_trace', 'runtime_trace'].includes(family)) {
              const events = data?.data?.events ?? data?.events ?? data?.data?.trace ?? data?.trace ?? data?.data?.api_calls ?? []
              for (const ev of events) {
                const api = ev.api ?? ev.name ?? ev.function
                if (api) dynamicApiSequence.push(api)
              }
            }
          } catch { /* skip */ }
        }
      }

      if (staticApis.length === 0 && dynamicApiSequence.length === 0) {
        return { ok: false, errors: ['No API data found for data flow analysis'] }
      }

      // Build a flow graph from dynamic sequence
      const nodes: FlowNode[] = []
      const edges: FlowEdge[] = []
      const nodeIds = new Set<string>()

      const apiSequence = dynamicApiSequence.length > 0 ? dynamicApiSequence : staticApis

      // Classify APIs
      function apiCategory(api: string): { category: string; direction: FlowNode['direction'] } {
        if (/ReadFile|RegQueryValue|FindResource|LoadResource|recv|InternetRead/i.test(api))
          return { category: 'input', direction: 'source' }
        if (/WriteFile|RegSetValue|send|HttpSendRequest|InternetWrite/i.test(api))
          return { category: 'output', direction: 'sink' }
        if (/Crypt|Hash|Compress|Decompress|Base64|XOR/i.test(api))
          return { category: 'transform', direction: 'transform' }
        if (/VirtualAlloc|VirtualProtect|CreateProcess|LoadLibrary|CreateRemoteThread/i.test(api))
          return { category: 'execution', direction: 'sink' }
        if (/CreateFile|URLDownload|InternetOpen|InternetConnect|WSAStartup|connect/i.test(api))
          return { category: 'setup', direction: 'source' }
        return { category: 'other', direction: 'transform' }
      }

      // Focus filter
      function matchesFocus(category: string): boolean {
        if (args.focus === 'all') return true
        if (args.focus === 'crypto' && (category === 'transform' || category === 'input' || category === 'output')) return true
        if (args.focus === 'network' && (category === 'setup' || category === 'output' || category === 'input')) return true
        if (args.focus === 'file_io' && (category === 'input' || category === 'output')) return true
        return false
      }

      // Build subsequence of interesting APIs
      const relevantApis = apiSequence.filter((api) => {
        const { category } = apiCategory(api)
        return matchesFocus(category) && category !== 'other'
      })

      // Add nodes and sequential edges
      for (let i = 0; i < Math.min(relevantApis.length, 200); i++) {
        const api = relevantApis[i]
        const { category, direction } = apiCategory(api)
        const id = `${api}_${i}`
        if (!nodeIds.has(id)) {
          nodeIds.add(id)
          nodes.push({ id, api, category, direction })
        }
        if (i > 0) {
          edges.push({
            from: `${relevantApis[i - 1]}_${i - 1}`,
            to: id,
            label: 'sequence',
          })
        }
      }

      // Pattern matching for known data flow chains
      const detectedPatterns: Array<{
        name: string
        description: string
        severity: string
        matched_apis: string[]
      }> = []

      const apiSet = new Set(apiSequence.map((a) => a.toLowerCase()))
      for (const pattern of DATA_FLOW_PATTERNS) {
        const matchIdx: number[] = []
        let searchFrom = 0
        let allFound = true
        for (const patApi of pattern.pattern) {
          let found = false
          for (let i = searchFrom; i < apiSequence.length; i++) {
            if (apiSequence[i].includes(patApi)) {
              matchIdx.push(i)
              searchFrom = i + 1
              found = true
              break
            }
          }
          if (!found) {
            if (!apiSet.has(patApi.toLowerCase()) && ![...apiSet].some((a) => a.includes(patApi.toLowerCase()))) {
              allFound = false
              break
            }
          }
        }

        if (allFound) {
          detectedPatterns.push({
            name: pattern.name,
            description: pattern.description,
            severity: pattern.severity,
            matched_apis: matchIdx.length === pattern.pattern.length
              ? matchIdx.map((i) => apiSequence[i])
              : pattern.pattern,
          })
        }
      }

      const resultData = {
        sample_id: args.sample_id,
        focus: args.focus,
        static_api_count: staticApis.length,
        dynamic_api_count: dynamicApiSequence.length,
        flow_node_count: nodes.length,
        flow_edge_count: edges.length,
        detected_patterns: detectedPatterns,
        flow_graph: {
          nodes: nodes.slice(0, 200),
          edges: edges.slice(0, 200),
        },
        data_sources: nodes.filter((n) => n.direction === 'source').map((n) => n.api),
        data_sinks: nodes.filter((n) => n.direction === 'sink').map((n) => n.api),
        data_transforms: nodes.filter((n) => n.direction === 'transform').map((n) => n.api),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'data_flow_map', 'data-flow-map', resultData
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
