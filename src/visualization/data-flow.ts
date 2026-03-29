/**
 * Data Flow Generator
 * Tasks: visualization-enhanced-reporting 2.1-2.5
 */

import { ExplanationGraphDigestSchema, type ExplanationGraphDigest } from '../explanation-graphs.js'

export interface DataFlowNode {
  id: string
  address: string
  name: string
  type: 'function' | 'data_source' | 'data_sink'
  dataType?: string
  isSuspicious: boolean
  confidence_state: 'observed' | 'correlated' | 'inferred'
}
export interface DataFlowEdge {
  source: string
  target: string
  dataType: string
  label?: string
  confidence_state: 'observed' | 'correlated' | 'inferred'
}
export interface DataFlowData {
  nodes: DataFlowNode[]
  edges: DataFlowEdge[]
  metadata: { sampleId: string; totalNodes: number; dataSources: number; dataSinks: number; trackedDataTypes: string[] }
  explanation: ExplanationGraphDigest
}
export interface DataFlowOptions { maxNodes?: number; trackDataTypes?: Array<'crypto_keys' | 'handles' | 'file_paths' | 'network_sockets' | 'buffers'>; format?: 'dot' | 'mermaid' | 'json'; sampleId?: string }

const DATA_TYPE_PATTERNS: Record<string, string[]> = {
  crypto_keys: ['CryptGenKey', 'CryptImportKey', 'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt', 'key', 'password', 'secret', 'aes', 'rc4'],
  handles: ['CreateFile', 'OpenProcess', 'hProcess', 'hThread', 'hFile'],
  file_paths: ['CreateFile', 'WriteFile', 'ReadFile', 'path', 'filename'],
  network_sockets: ['socket', 'connect', 'send', 'recv', 'InternetOpen', 'HttpSendRequest'],
  buffers: ['VirtualAlloc', 'HeapAlloc', 'malloc', 'memcpy', 'buffer'],
}

export function generateDataFlow(functions: Array<{ address: string; name: string; score: number; calledApis?: string[]; referencedStrings?: string[] }>, options: DataFlowOptions = {}): DataFlowData {
  const { maxNodes = 30, trackDataTypes = Object.keys(DATA_TYPE_PATTERNS) as Array<keyof typeof DATA_TYPE_PATTERNS> } = options
  const nodes: DataFlowNode[] = []; const edges: DataFlowEdge[] = []; const nodeMap = new Map<string, DataFlowNode>()

  for (const func of functions.slice(0, maxNodes)) {
    const calledApis = func.calledApis || []
    for (const dataType of trackDataTypes) {
      const patterns = DATA_TYPE_PATTERNS[dataType]
      const matches = calledApis.filter(api => patterns.some(p => p.toLowerCase().includes(api.toLowerCase()) || api.toLowerCase().includes(p.toLowerCase())))
      if (matches.length > 0) {
        const sourceId = `${func.address}_source_${dataType}`
        if (!nodeMap.has(sourceId)) {
          const sourceNode: DataFlowNode = { id: sourceId, address: func.address, name: `${func.name} (source)`, type: 'data_source', dataType, isSuspicious: func.score > 0.7, confidence_state: 'inferred' }
          nodes.push(sourceNode); nodeMap.set(sourceId, sourceNode)
        }
        edges.push({ source: func.address, target: sourceId, dataType, label: matches[0], confidence_state: 'inferred' })
      }
    }
    const sinkPatterns = ['WriteFile', 'send', 'recv', 'CryptEncrypt', 'CryptDecrypt']
    const sinkMatches = calledApis.filter(api => sinkPatterns.some(p => api.toLowerCase().includes(p.toLowerCase())))
    if (sinkMatches.length > 0) {
      const sinkId = `${func.address}_sink`
      if (!nodeMap.has(sinkId)) {
        const sinkNode: DataFlowNode = { id: sinkId, address: func.address, name: `${func.name} (sink)`, type: 'data_sink', isSuspicious: func.score > 0.7, confidence_state: 'inferred' }
        nodes.push(sinkNode); nodeMap.set(sinkId, sinkNode)
      }
    }
    const funcNode: DataFlowNode = { id: func.address, address: func.address, name: func.name, type: 'function', isSuspicious: func.score > 0.7, confidence_state: 'correlated' }
    nodes.push(funcNode); nodeMap.set(func.address, funcNode)
  }

  const trackedDataTypes = Array.from(new Set(nodes.filter(n => n.dataType).map(n => n.dataType!)))
  const explanation = ExplanationGraphDigestSchema.parse({
    graph_type: 'data_flow',
    surface_role: 'explanation_artifact',
    title: 'Bounded Data-Flow Explanation',
    semantic_summary:
      nodes.length > 0
        ? `Heuristic data-flow explanation over ${nodes.length} bounded node(s), emphasizing API-pattern-derived sources and sinks rather than claiming exact whole-program taint coverage.`
        : 'No bounded data-flow explanation could be derived from the currently available persisted functions.',
    confidence_state: 'inferred',
    confidence_states_present: ['correlated', 'inferred'],
    confidence_score: nodes.length > 0 ? 0.54 : 0.24,
    node_count: nodes.length,
    edge_count: edges.length,
    bounded: true,
    available_serializers: ['json', 'dot', 'mermaid'],
    provenance: [
      {
        kind: 'heuristic',
        label: 'api_pattern_matching',
        detail: 'Sources and sinks are inferred from bounded API-name patterns rather than from full data-flow reconstruction.',
      },
      {
        kind: 'selection',
        label: 'bounded_function_subset',
        detail: `Examined at most ${maxNodes} function(s) while building this explanation.`,
      },
    ],
    omissions: [
      {
        code: 'no_precise_taint_engine',
        reason: 'This graph does not claim exact observed data movement; it is a bounded correlation surface for analyst guidance.',
      },
      ...(functions.length > maxNodes
        ? [
            {
              code: 'bounded_function_selection',
              reason: `Omitted ${functions.length - maxNodes} lower-priority function(s) to preserve bounded graph size.`,
            },
          ]
        : []),
    ],
    recommended_next_tools: ['analysis.context.link', 'crypto.identify', 'workflow.analyze.promote'],
  })

  return {
    nodes,
    edges,
    metadata: {
      sampleId: options.sampleId || '',
      totalNodes: nodes.length,
      dataSources: nodes.filter(n => n.type === 'data_source').length,
      dataSinks: nodes.filter(n => n.type === 'data_sink').length,
      trackedDataTypes,
    },
    explanation,
  }
}

export function dataFlowToDot(data: DataFlowData, options?: { title?: string }): string {
  const { title = 'Data Flow Diagram' } = options || {}
  let dot = `digraph "${title}" {\n  rankdir=LR;\n  node [shape=box, style=rounded];\n\n`
  for (const node of data.nodes) {
    let shape = 'box', color = 'black', fillcolor = 'white', style = 'solid'
    if (node.type === 'data_source') { shape = 'ellipse'; fillcolor = 'lightblue'; style = 'filled' }
    else if (node.type === 'data_sink') { shape = 'doubleoctagon'; fillcolor = 'lightcoral'; style = 'filled' }
    if (node.isSuspicious) { color = 'red'; style = 'filled,bold' }
    const label = node.dataType ? `${escapeDot(node.name)}\\n${node.dataType}` : escapeDot(node.name)
    dot += `  "${node.id}" [label="${label}", shape="${shape}", color="${color}", style="${style}", fillcolor="${fillcolor}"];\n`
  }
  dot += '\n'
  for (const edge of data.edges) dot += `  "${edge.source}" -> "${edge.target}" [label="${escapeDot(edge.label || edge.dataType)}", color="gray"];\n`
  return dot + '}\n'
}

export function dataFlowToMermaid(data: DataFlowData): string {
  let mermaid = 'graph LR\n'
  for (const node of data.nodes) {
    let shape = '["', endShape = '"]'
    if (node.type === 'data_source') { shape = '(('; endShape = '))' }
    else if (node.type === 'data_sink') { shape = '[('; endShape = ')]' }
    const label = node.dataType ? `${escapeMermaid(node.name)}\\n${node.dataType}` : escapeMermaid(node.name)
    mermaid += `  ${node.id}${shape}${label}${endShape}\n`
    if (node.isSuspicious) mermaid += `  ${node.id}:::suspicious\n`
  }
  mermaid += '\n'
  for (const edge of data.edges) mermaid += `  ${edge.source} -->|${escapeMermaid(edge.label || edge.dataType)}| ${edge.target}\n`
  return mermaid + '\nclassDef suspicious fill:#ffcccc,stroke:red,stroke-width:2px;\nclassDef data_source fill:lightblue,stroke:blue;\nclassDef data_sink fill:lightcoral,stroke:darkred;\n'
}

function escapeDot(text: string): string { return text.replace(/"/g, '\\"').replace(/\n/g, '\\n') }
function escapeMermaid(text: string): string { return text.replace(/"/g, "'").replace(/\n/g, ' ') }
