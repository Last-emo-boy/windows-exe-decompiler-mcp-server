/**
 * Call Graph Generator
 * Tasks: visualization-enhanced-reporting 1.1-1.5
 */

import {
  ExplanationGraphDigestSchema,
  type ExplanationGraphDigest,
} from '../explanation-graphs.js'

type ExplanationConfidenceState = 'observed' | 'correlated' | 'inferred'

export interface CallGraphNode {
  id: string
  address: string
  name: string
  size: number
  score: number
  isSuspicious: boolean
  callerCount: number
  calleeCount: number
  confidence_state: ExplanationConfidenceState
}
export interface CallGraphEdge {
  source: string
  target: string
  callCount: number
  confidence_state: ExplanationConfidenceState
}
export interface CallGraphData {
  nodes: CallGraphNode[]
  edges: CallGraphEdge[]
  metadata: { sampleId: string; totalFunctions: number; suspiciousFunctions: number; maxDepth: number; selectedFunctions: number }
  explanation: ExplanationGraphDigest
}
export interface CallGraphOptions { maxNodes?: number; highlightSuspicious?: boolean; format?: 'dot' | 'mermaid' | 'json'; sampleId?: string }

export function generateCallGraph(
  functions: Array<{
    address: string
    name: string
    size: number
    score: number
    callers?: string[]
    callees?: string[]
    callerCount?: number
    calleeCount?: number
  }>,
  options: CallGraphOptions = {}
): CallGraphData {
  const { maxNodes = 50, highlightSuspicious = true } = options
  const sortedFunctions = [...functions].sort((a, b) => b.score - a.score)
  const selectedFunctions = sortedFunctions.slice(0, maxNodes)
  
  const nodes: CallGraphNode[] = selectedFunctions.map(func => ({
    id: func.address, address: func.address, name: func.name, size: func.size, score: func.score,
    isSuspicious: highlightSuspicious && func.score > 0.7,
    callerCount: func.callers?.length || func.callerCount || 0, calleeCount: func.callees?.length || func.calleeCount || 0,
    confidence_state: 'correlated',
  }))
  
  const edges: CallGraphEdge[] = []
  const edgeMap = new Map<string, CallGraphEdge>()
  for (const func of selectedFunctions) {
    if (func.callees) {
      for (const callee of func.callees) {
        const edgeKey = `${func.address}->${callee}`
        if (edgeMap.has(edgeKey)) edgeMap.get(edgeKey)!.callCount++
        else {
          const edge: CallGraphEdge = {
            source: func.address,
            target: callee,
            callCount: 1,
            confidence_state: 'correlated',
          }
          edgeMap.set(edgeKey, edge); edges.push(edge)
        }
      }
    }
  }

  const omissions =
    functions.length > selectedFunctions.length
      ? [
          {
            code: 'bounded_node_selection',
            reason: `Omitted ${functions.length - selectedFunctions.length} lower-priority functions to keep the graph bounded.`,
          },
        ]
      : undefined

  const explanation = ExplanationGraphDigestSchema.parse({
    graph_type: 'call_graph',
    surface_role: 'local_navigation_aid',
    title: 'Bounded Call Graph',
    semantic_summary:
      selectedFunctions.length > 0
        ? `Bounded local call-relationship view over ${selectedFunctions.length} higher-signal function(s); use it for navigation and hotspot selection rather than as a whole-program truth claim.`
        : 'No persisted function relationships were available to build a bounded call-graph explanation.',
    confidence_state: 'correlated',
    confidence_states_present: ['correlated'],
    confidence_score:
      selectedFunctions.length > 0
        ? Math.min(
            0.92,
            Math.max(
              0.42,
              selectedFunctions.reduce((sum, item) => sum + Math.max(0, item.score || 0), 0) /
                selectedFunctions.length
            )
          )
        : 0.3,
    node_count: nodes.length,
    edge_count: edges.length,
    bounded: true,
    available_serializers: ['json', 'dot', 'mermaid'],
    provenance: [
      {
        kind: 'stage',
        label: 'persisted_function_index',
        detail: 'Built from persisted function-score and callee relationship data already present in the workspace.',
      },
      {
        kind: 'selection',
        label: 'top_signal_subset',
        detail: `Selected the top ${selectedFunctions.length} function(s) by score before rendering.`,
      },
    ],
    omissions,
    recommended_next_tools: ['code.function.cfg', 'code.function.decompile', 'workflow.analyze.promote'],
  })

  return {
    nodes,
    edges,
    metadata: {
      sampleId: options.sampleId || '',
      totalFunctions: functions.length,
      suspiciousFunctions: nodes.filter(n => n.isSuspicious).length,
      maxDepth: calculateMaxDepth(nodes, edges),
      selectedFunctions: selectedFunctions.length,
    },
    explanation,
  }
}

export function callGraphToDot(graph: CallGraphData, options?: { title?: string }): string {
  const { title = 'Function Call Graph' } = options || {}
  let dot = `digraph "${title}" {\n  rankdir=TB;\n  node [shape=box, style=rounded];\n\n`
  for (const node of graph.nodes) {
    const color = node.isSuspicious ? 'red' : 'black'
    const style = node.isSuspicious ? 'filled' : 'solid'
    const fillcolor = node.isSuspicious ? '#ffcccc' : 'white'
    dot += `  "${node.address}" [label="${escapeDot(node.name)}\\n${node.address}", color="${color}", style="${style}", fillcolor="${fillcolor}"];\n`
  }
  dot += '\n'
  for (const edge of graph.edges) {
    dot += `  "${edge.source}" -> "${edge.target}" [label="${edge.callCount}", color="${edge.callCount > 1 ? 'red' : 'gray'}"];\n`
  }
  return dot + '}\n'
}

export function callGraphToMermaid(graph: CallGraphData): string {
  let mermaid = 'graph TB\n'
  for (const node of graph.nodes) {
    mermaid += `  ${node.id}["${escapeMermaid(node.name)}"]\n`
    if (node.isSuspicious) mermaid += `  ${node.id}:::suspicious\n`
  }
  mermaid += '\n'
  for (const edge of graph.edges) mermaid += `  ${edge.source} --> ${edge.target}\n`
  return mermaid + '\nclassDef suspicious fill:#ffcccc,stroke:red,stroke-width:2px;\n'
}

function escapeDot(text: string): string { return text.replace(/"/g, '\\"').replace(/\n/g, '\\n') }
function escapeMermaid(text: string): string { return text.replace(/"/g, "'") }
function calculateMaxDepth(nodes: CallGraphNode[], edges: CallGraphEdge[]): number {
  if (nodes.length === 0) return 0
  const adjacency = new Map<string, string[]>()
  for (const edge of edges) { if (!adjacency.has(edge.source)) adjacency.set(edge.source, []); adjacency.get(edge.source)!.push(edge.target) }
  const visited = new Set<string>(); let maxDepth = 0
  function dfs(nodeId: string, depth: number): void {
    if (visited.has(nodeId)) return
    visited.add(nodeId); maxDepth = Math.max(maxDepth, depth)
    const neighbors = adjacency.get(nodeId) || []
    for (const neighbor of neighbors) dfs(neighbor, depth + 1)
  }
  const hasIncoming = new Set(edges.map(e => e.target))
  const roots = nodes.filter(n => !hasIncoming.has(n.address))
  for (const root of roots) { visited.clear(); dfs(root.address, 1) }
  return maxDepth
}
