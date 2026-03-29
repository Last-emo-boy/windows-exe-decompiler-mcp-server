import fs from 'fs/promises'
import path from 'path'
import { spawnSync } from 'child_process'
import { createHash, randomUUID } from 'crypto'
import type { DatabaseManager, Function as DatabaseFunction } from './database.js'
import type { ControlFlowGraph, CFGEdge, CFGNode } from './decompiler-worker.js'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'

export type CFGExportFormat = 'json' | 'dot' | 'mermaid'
export type CFGRenderFormat = 'none' | 'svg' | 'png'

export interface GraphTextPreview {
  format: CFGExportFormat
  inline_text?: string
  inline_json?: unknown
  truncated: boolean
  preview_char_count?: number
  preview_node_count?: number
  preview_edge_count?: number
  omitted_nodes?: number
  omitted_edges?: number
  full_output_available: boolean
}

export interface CFGGraphSummary {
  function: string
  address: string
  node_count: number
  edge_count: number
  block_type_counts: Record<string, number>
  entry_node_count: number
  exit_node_count: number
}

export interface GraphTextExport {
  format: CFGExportFormat
  text: string
  preview: GraphTextPreview
}

export interface LocalCallGraphNode {
  id: string
  name: string
  address: string | null
  role: 'root' | 'caller' | 'callee' | 'transitive' | 'external'
  internal: boolean
}

export interface LocalCallGraphEdge {
  from: string
  to: string
  relation: 'calls'
  depth: number
}

export interface LocalCallGraph {
  root: {
    id: string
    name: string
    address: string | null
  }
  nodes: LocalCallGraphNode[]
  edges: LocalCallGraphEdge[]
  bounded: true
  depth: number
  limit: number
  truncated: boolean
  note: string
}

export interface GraphvizAvailability {
  available: boolean
  backend: 'graphviz' | 'none'
  version: string | null
  error?: string
}

export interface PersistGraphArtifactOptions {
  sampleId: string
  functionName: string
  functionAddress: string
  format: CFGExportFormat | 'svg' | 'png'
  scope: 'cfg' | 'call_relationships'
  sessionTag?: string | null
  renderBackend?: string | null
}

const GRAPH_ARTIFACT_TYPE_BY_FORMAT: Record<CFGExportFormat | 'svg' | 'png', string> = {
  json: 'cfg_graph_json',
  dot: 'cfg_graph_dot',
  mermaid: 'cfg_graph_mermaid',
  svg: 'cfg_graph_svg',
  png: 'cfg_graph_png',
}

const FILE_EXTENSION_BY_FORMAT: Record<CFGExportFormat | 'svg' | 'png', string> = {
  json: 'json',
  dot: 'dot',
  mermaid: 'mmd',
  svg: 'svg',
  png: 'png',
}

const MIME_BY_FORMAT: Record<CFGExportFormat | 'svg' | 'png', string> = {
  json: 'application/json',
  dot: 'text/vnd.graphviz',
  mermaid: 'text/plain',
  svg: 'image/svg+xml',
  png: 'image/png',
}

function sanitizeSegment(value: string | null | undefined, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

function sha256ForContent(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex')
}

function buildArtifactRef(ref: {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string | null
  metadata?: Record<string, unknown>
}): ArtifactRef {
  return {
    id: ref.id,
    type: ref.type,
    path: ref.path,
    sha256: ref.sha256,
    ...(ref.mime ? { mime: ref.mime } : {}),
    ...(ref.metadata ? { metadata: ref.metadata } : {}),
  }
}

function escapeGraphLabel(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function escapeMermaidText(value: string): string {
  return value.replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function sortNodes(nodes: CFGNode[]): CFGNode[] {
  return [...nodes].sort(
    (left, right) =>
      left.address.localeCompare(right.address) ||
      left.id.localeCompare(right.id) ||
      left.type.localeCompare(right.type)
  )
}

function sortEdges(edges: CFGEdge[]): CFGEdge[] {
  return [...edges].sort(
    (left, right) =>
      left.from.localeCompare(right.from) ||
      left.to.localeCompare(right.to) ||
      left.type.localeCompare(right.type)
  )
}

function instructionPreviewLines(instructions: string[], limit = 4): string[] {
  return instructions
    .slice(0, limit)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

function buildCFGNodeLabel(node: CFGNode): string {
  const lines = [node.address, `type=${node.type}`, ...instructionPreviewLines(node.instructions)]
  return lines.join('\n')
}

function buildMermaidCFGNodeLabel(node: CFGNode): string {
  const lines = [node.address, node.type, ...instructionPreviewLines(node.instructions)]
  return lines.map((line) => escapeMermaidText(line)).join('<br/>')
}

function nodeShape(type: CFGNode['type']): string {
  switch (type) {
    case 'entry':
      return 'oval'
    case 'exit':
      return 'doublecircle'
    case 'call':
      return 'component'
    case 'return':
      return 'parallelogram'
    default:
      return 'box'
  }
}

function nodeFill(type: CFGNode['type']): string {
  switch (type) {
    case 'entry':
      return '#e8f5e9'
    case 'exit':
      return '#ffebee'
    case 'call':
      return '#e3f2fd'
    case 'return':
      return '#fff3e0'
    default:
      return '#fafafa'
  }
}

function edgeColor(type: CFGEdge['type']): string {
  switch (type) {
    case 'jump':
      return '#ef6c00'
    case 'call':
      return '#1565c0'
    case 'return':
      return '#2e7d32'
    default:
      return '#616161'
  }
}

export function buildCFGSummary(cfg: ControlFlowGraph): CFGGraphSummary {
  const blockTypeCounts = cfg.nodes.reduce<Record<string, number>>((acc, node) => {
    acc[node.type] = (acc[node.type] || 0) + 1
    return acc
  }, {})

  return {
    function: cfg.function,
    address: cfg.address,
    node_count: cfg.nodes.length,
    edge_count: cfg.edges.length,
    block_type_counts: blockTypeCounts,
    entry_node_count: cfg.nodes.filter((node) => node.type === 'entry').length,
    exit_node_count: cfg.nodes.filter((node) => node.type === 'exit').length,
  }
}

export function buildCompactCFGJsonPreview(
  cfg: ControlFlowGraph,
  maxNodes: number,
  maxEdges: number
): GraphTextPreview {
  const sortedNodes = sortNodes(cfg.nodes)
  const sortedEdges = sortEdges(cfg.edges)
  const previewNodes = sortedNodes.slice(0, maxNodes).map((node) => ({
    id: node.id,
    address: node.address,
    type: node.type,
    instruction_count: node.instructions.length,
    instructions_preview: instructionPreviewLines(node.instructions),
    instructions_truncated: node.instructions.length > 4,
  }))
  const previewEdges = sortedEdges.slice(0, maxEdges).map((edge) => ({
    from: edge.from,
    to: edge.to,
    type: edge.type,
  }))

  return {
    format: 'json',
    inline_json: {
      nodes: previewNodes,
      edges: previewEdges,
    },
    truncated: sortedNodes.length > maxNodes || sortedEdges.length > maxEdges,
    preview_node_count: previewNodes.length,
    preview_edge_count: previewEdges.length,
    omitted_nodes: Math.max(0, sortedNodes.length - previewNodes.length),
    omitted_edges: Math.max(0, sortedEdges.length - previewEdges.length),
    full_output_available: true,
  }
}

function buildTextPreview(
  format: Exclude<CFGExportFormat, 'json'>,
  text: string,
  maxChars: number
): GraphTextPreview {
  const inlineText = text.length > maxChars ? `${text.slice(0, maxChars)}\n...` : text
  return {
    format,
    inline_text: inlineText,
    truncated: text.length > maxChars,
    preview_char_count: inlineText.length,
    full_output_available: true,
  }
}

export function buildDOTFromCFG(cfg: ControlFlowGraph): string {
  const lines: string[] = []
  lines.push(`digraph "${escapeGraphLabel(cfg.function)}" {`)
  lines.push('  rankdir=TB;')
  lines.push('  node [fontname="Courier New", fontsize=10, style="filled"];')
  lines.push('  edge [fontname="Courier New", fontsize=9];')

  for (const node of sortNodes(cfg.nodes)) {
    lines.push(
      `  "${escapeGraphLabel(node.id)}" [` +
        `label="${escapeGraphLabel(buildCFGNodeLabel(node))}", ` +
        `shape="${nodeShape(node.type)}", ` +
        `fillcolor="${nodeFill(node.type)}"` +
        '];'
    )
  }

  for (const edge of sortEdges(cfg.edges)) {
    lines.push(
      `  "${escapeGraphLabel(edge.from)}" -> "${escapeGraphLabel(edge.to)}" ` +
        `[label="${escapeGraphLabel(edge.type)}", color="${edgeColor(edge.type)}"];`
    )
  }

  lines.push('}')
  return lines.join('\n')
}

export function buildMermaidFromCFG(cfg: ControlFlowGraph): string {
  const sortedNodes = sortNodes(cfg.nodes)
  const nodeIds = new Map<string, string>()
  sortedNodes.forEach((node, index) => {
    nodeIds.set(node.id, `n${index}`)
  })

  const lines: string[] = ['flowchart TD']
  for (const node of sortedNodes) {
    const mermaidId = nodeIds.get(node.id) || sanitizeSegment(node.id, 'node')
    lines.push(`  ${mermaidId}["${buildMermaidCFGNodeLabel(node)}"]`)
  }

  for (const edge of sortEdges(cfg.edges)) {
    const from = nodeIds.get(edge.from) || sanitizeSegment(edge.from, 'from')
    const to = nodeIds.get(edge.to) || sanitizeSegment(edge.to, 'to')
    lines.push(`  ${from} -->|${escapeMermaidText(edge.type)}| ${to}`)
  }

  lines.push('  classDef entry fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20;')
  lines.push('  classDef exit fill:#ffebee,stroke:#c62828,color:#7f0000;')
  lines.push('  classDef call fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;')
  lines.push('  classDef return fill:#fff3e0,stroke:#ef6c00,color:#e65100;')
  lines.push('  classDef basic fill:#fafafa,stroke:#616161,color:#212121;')

  for (const node of sortedNodes) {
    const mermaidId = nodeIds.get(node.id) || sanitizeSegment(node.id, 'node')
    lines.push(`  class ${mermaidId} ${node.type};`)
  }

  return lines.join('\n')
}

export function buildCFGExport(
  cfg: ControlFlowGraph,
  format: CFGExportFormat,
  previewMaxChars: number,
  previewMaxNodes: number,
  previewMaxEdges: number
): GraphTextExport {
  if (format === 'json') {
    return {
      format,
      text: JSON.stringify(cfg, null, 2),
      preview: buildCompactCFGJsonPreview(cfg, previewMaxNodes, previewMaxEdges),
    }
  }

  const text = format === 'dot' ? buildDOTFromCFG(cfg) : buildMermaidFromCFG(cfg)
  return {
    format,
    text,
    preview: buildTextPreview(format, text, previewMaxChars),
  }
}

function parseCallees(raw: string | null | undefined): string[] {
  if (!raw) {
    return []
  }
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

function choosePreferredFunction(
  candidates: DatabaseFunction[] | undefined,
  expectedAddress?: string
): DatabaseFunction | undefined {
  if (!candidates || candidates.length === 0) {
    return undefined
  }
  if (expectedAddress) {
    const exact = candidates.find((item) => item.address === expectedAddress)
    if (exact) {
      return exact
    }
  }
  return [...candidates].sort((left, right) => left.address.localeCompare(right.address))[0]
}

function buildCallerAndCalleeIndexes(functions: DatabaseFunction[]) {
  const byAddress = new Map<string, DatabaseFunction>()
  const byName = new Map<string, DatabaseFunction[]>()
  const inboundByAddress = new Map<string, DatabaseFunction[]>()

  for (const func of functions) {
    byAddress.set(func.address, func)
    if (func.name) {
      byName.set(func.name, [...(byName.get(func.name) || []), func].sort((a, b) => a.address.localeCompare(b.address)))
    }
  }

  for (const func of functions) {
    for (const calleeName of parseCallees(func.callees)) {
      const preferred = choosePreferredFunction(byName.get(calleeName))
      if (!preferred) {
        continue
      }
      const currentInbound = inboundByAddress.get(preferred.address) || []
      currentInbound.push(func)
      inboundByAddress.set(
        preferred.address,
        currentInbound.sort(
          (left, right) => left.address.localeCompare(right.address) || left.name.localeCompare(right.name)
        )
      )
    }
  }

  return {
    byAddress,
    byName,
    inboundByAddress,
  }
}

function upsertCallNode(
  nodes: Map<string, LocalCallGraphNode>,
  candidate: LocalCallGraphNode
): void {
  const existing = nodes.get(candidate.id)
  if (!existing) {
    nodes.set(candidate.id, candidate)
    return
  }

  if (existing.role !== candidate.role && existing.role !== 'root' && candidate.role !== 'root') {
    nodes.set(candidate.id, {
      ...existing,
      role: existing.internal && candidate.internal ? 'transitive' : existing.role,
    })
  }
}

export function buildLocalCallGraphPreview(
  functions: DatabaseFunction[],
  cfg: ControlFlowGraph,
  depth: number,
  limit: number
): LocalCallGraph {
  const normalizedDepth = Math.min(Math.max(depth, 1), 2)
  const normalizedLimit = Math.min(Math.max(limit, 1), 32)
  const { byAddress, byName, inboundByAddress } = buildCallerAndCalleeIndexes(functions)
  const rootFunction =
    byAddress.get(cfg.address) || choosePreferredFunction(byName.get(cfg.function), cfg.address)

  const rootId = rootFunction?.address || cfg.address
  const rootNode: LocalCallGraphNode = {
    id: rootId,
    name: rootFunction?.name || cfg.function,
    address: rootFunction?.address || cfg.address,
    role: 'root',
    internal: true,
  }

  const nodes = new Map<string, LocalCallGraphNode>([[rootNode.id, rootNode]])
  const edges = new Map<string, LocalCallGraphEdge>()
  const seen = new Set<string>([rootNode.id])
  const queue: Array<{ func: DatabaseFunction; depth: number }> = rootFunction
    ? [{ func: rootFunction, depth: 0 }]
    : []
  let truncated = false

  const addEdge = (edge: LocalCallGraphEdge) => {
    const key = `${edge.from}->${edge.to}:${edge.depth}`
    if (edges.has(key)) {
      return true
    }
    if (edges.size >= normalizedLimit) {
      truncated = true
      return false
    }
    edges.set(key, edge)
    return true
  }

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) {
      break
    }
    if (current.depth >= normalizedDepth) {
      continue
    }

    const currentCallees = parseCallees(current.func.callees)
    for (const calleeName of currentCallees) {
      const internalTarget = choosePreferredFunction(byName.get(calleeName))
      const targetNode: LocalCallGraphNode = internalTarget
        ? {
            id: internalTarget.address,
            name: internalTarget.name,
            address: internalTarget.address,
            role: current.depth === 0 ? 'callee' : 'transitive',
            internal: true,
          }
        : {
            id: `external:${calleeName}`,
            name: calleeName,
            address: null,
            role: 'external',
            internal: false,
          }

      upsertCallNode(nodes, targetNode)
      if (!addEdge({ from: current.func.address, to: targetNode.id, relation: 'calls', depth: current.depth + 1 })) {
        break
      }

      if (internalTarget && current.depth + 1 < normalizedDepth && !seen.has(internalTarget.address)) {
        seen.add(internalTarget.address)
        queue.push({ func: internalTarget, depth: current.depth + 1 })
      }
    }

    const callers = inboundByAddress.get(current.func.address) || []
    for (const caller of callers) {
      const callerNode: LocalCallGraphNode = {
        id: caller.address,
        name: caller.name,
        address: caller.address,
        role: current.depth === 0 ? 'caller' : 'transitive',
        internal: true,
      }
      upsertCallNode(nodes, callerNode)
      if (!addEdge({ from: caller.address, to: current.func.address, relation: 'calls', depth: current.depth + 1 })) {
        break
      }

      if (current.depth + 1 < normalizedDepth && !seen.has(caller.address)) {
        seen.add(caller.address)
        queue.push({ func: caller, depth: current.depth + 1 })
      }
    }
  }

  return {
    root: {
      id: rootNode.id,
      name: rootNode.name,
      address: rootNode.address,
    },
    nodes: [...nodes.values()].sort(
      (left, right) =>
        (left.address || left.id).localeCompare(right.address || right.id) ||
        left.name.localeCompare(right.name)
    ),
    edges: [...edges.values()].sort(
      (left, right) =>
        left.from.localeCompare(right.from) ||
        left.to.localeCompare(right.to) ||
        left.depth - right.depth
    ),
    bounded: true,
    depth: normalizedDepth,
    limit: normalizedLimit,
    truncated,
    note: `Bounded local call graph preview around ${rootNode.name}. Depth=${normalizedDepth}, edge_limit=${normalizedLimit}; this is not a whole-program call graph.`,
  }
}

function buildCallNodeLabel(node: LocalCallGraphNode): string {
  return [node.address || 'external', node.name, `role=${node.role}`].join('\n')
}

export function buildDOTFromLocalCallGraph(graph: LocalCallGraph): string {
  const lines: string[] = []
  lines.push(`digraph "${escapeGraphLabel(graph.root.name)}_calls" {`)
  lines.push('  rankdir=LR;')
  lines.push('  node [fontname="Courier New", fontsize=10, style="filled"];')
  lines.push('  edge [fontname="Courier New", fontsize=9];')

  for (const node of graph.nodes) {
    lines.push(
      `  "${escapeGraphLabel(node.id)}" [` +
        `label="${escapeGraphLabel(buildCallNodeLabel(node))}", ` +
        `shape="${node.role === 'external' ? 'note' : node.role === 'root' ? 'oval' : 'box'}", ` +
        `fillcolor="${node.role === 'root' ? '#e8f5e9' : node.role === 'caller' ? '#fff3e0' : node.role === 'callee' ? '#e3f2fd' : node.role === 'external' ? '#f3e5f5' : '#fafafa'}"` +
        '];'
    )
  }

  for (const edge of graph.edges) {
    lines.push(
      `  "${escapeGraphLabel(edge.from)}" -> "${escapeGraphLabel(edge.to)}" ` +
        `[label="depth=${edge.depth}", color="#616161"];`
    )
  }

  lines.push('}')
  return lines.join('\n')
}

export function buildMermaidFromLocalCallGraph(graph: LocalCallGraph): string {
  const sortedNodes = [...graph.nodes].sort(
    (left, right) =>
      (left.address || left.id).localeCompare(right.address || right.id) || left.name.localeCompare(right.name)
  )
  const nodeIds = new Map<string, string>()
  sortedNodes.forEach((node, index) => {
    nodeIds.set(node.id, `c${index}`)
  })

  const lines: string[] = ['flowchart LR']
  for (const node of sortedNodes) {
    const mermaidId = nodeIds.get(node.id) || sanitizeSegment(node.id, 'call')
    const label = [node.address || 'external', node.name, node.role]
      .map((item) => escapeMermaidText(item))
      .join('<br/>')
    lines.push(`  ${mermaidId}["${label}"]`)
  }

  for (const edge of graph.edges) {
    const from = nodeIds.get(edge.from) || sanitizeSegment(edge.from, 'from')
    const to = nodeIds.get(edge.to) || sanitizeSegment(edge.to, 'to')
    lines.push(`  ${from} -->|d${edge.depth}| ${to}`)
  }

  lines.push('  classDef root fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20;')
  lines.push('  classDef caller fill:#fff3e0,stroke:#ef6c00,color:#e65100;')
  lines.push('  classDef callee fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;')
  lines.push('  classDef transitive fill:#fafafa,stroke:#616161,color:#212121;')
  lines.push('  classDef external fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c;')

  for (const node of sortedNodes) {
    const mermaidId = nodeIds.get(node.id) || sanitizeSegment(node.id, 'call')
    lines.push(`  class ${mermaidId} ${node.role};`)
  }

  return lines.join('\n')
}

export function buildLocalCallGraphExport(
  graph: LocalCallGraph,
  format: CFGExportFormat,
  previewMaxChars: number
): GraphTextExport {
  if (format === 'json') {
    return {
      format,
      text: JSON.stringify(graph, null, 2),
      preview: {
        format,
        inline_json: {
          root: graph.root,
          nodes: graph.nodes.slice(0, 12),
          edges: graph.edges.slice(0, 16),
          note: graph.note,
        },
        truncated: graph.truncated || graph.nodes.length > 12 || graph.edges.length > 16,
        preview_node_count: Math.min(graph.nodes.length, 12),
        preview_edge_count: Math.min(graph.edges.length, 16),
        omitted_nodes: Math.max(0, graph.nodes.length - 12),
        omitted_edges: Math.max(0, graph.edges.length - 16),
        full_output_available: true,
      },
    }
  }

  const text = format === 'dot' ? buildDOTFromLocalCallGraph(graph) : buildMermaidFromLocalCallGraph(graph)
  return {
    format,
    text,
    preview: buildTextPreview(format, text, previewMaxChars),
  }
}

export function detectGraphvizAvailability(): GraphvizAvailability {
  try {
    const result = spawnSync('dot', ['-V'], {
      encoding: 'utf8',
      timeout: 3000,
    })

    if (result.error) {
      return {
        available: false,
        backend: 'none',
        version: null,
        error: result.error.message,
      }
    }

    const combinedOutput = [result.stdout, result.stderr].filter(Boolean).join(' ').trim()
    if (result.status !== 0 && combinedOutput.length === 0) {
      return {
        available: false,
        backend: 'none',
        version: null,
        error: `dot exited with status ${result.status}`,
      }
    }

    return {
      available: true,
      backend: 'graphviz',
      version: combinedOutput || null,
    }
  } catch (error) {
    return {
      available: false,
      backend: 'none',
      version: null,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

export function buildGraphvizSetupActions() {
  return [
    {
      id: 'install_graphviz',
      required: false,
      kind: 'install_package',
      title: 'Install Graphviz',
      summary: 'Install the Graphviz dot renderer to enable code.function.cfg render=svg or render=png.',
      command: 'apt-get update && apt-get install -y graphviz',
      examples: [
        'apt-get update && apt-get install -y graphviz',
        'brew install graphviz',
        'choco install graphviz',
      ],
      applies_to: ['code.function.cfg'],
    },
  ]
}

export async function persistGraphArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  content: string | Buffer,
  options: PersistGraphArtifactOptions
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(options.sampleId)
  const sessionSegment = sanitizeSegment(options.sessionTag || undefined, 'default')
  const scopeSegment = options.scope === 'cfg' ? 'cfg' : 'callgraph'
  const reportDir = path.join(workspace.reports, 'graphs', sessionSegment, scopeSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const functionSegment = sanitizeSegment(options.functionName || options.functionAddress, 'function')
  const addressSegment = sanitizeSegment(options.functionAddress, 'addr')
  const fileName = `${scopeSegment}_${functionSegment}_${addressSegment}_${Date.now()}.${FILE_EXTENSION_BY_FORMAT[options.format]}`
  const absolutePath = path.join(reportDir, fileName)
  await fs.writeFile(absolutePath, content)

  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const artifactId = randomUUID()
  const createdAt = new Date().toISOString()
  const sha256 = sha256ForContent(content)
  const type = GRAPH_ARTIFACT_TYPE_BY_FORMAT[options.format]
  const mime = MIME_BY_FORMAT[options.format]

  database.insertArtifact({
    id: artifactId,
    sample_id: options.sampleId,
    type,
    path: relativePath,
    sha256,
    mime,
    created_at: createdAt,
  })

  return buildArtifactRef({
    id: artifactId,
    type,
    path: relativePath,
    sha256,
    mime,
    metadata: {
      session_tag: options.sessionTag || null,
      artifact_family: 'graphs',
      graph_scope: options.scope,
      graph_format: options.format,
      graph_surface_role: 'local_navigation_aid',
      graph_confidence_state: options.scope === 'cfg' ? 'observed' : 'correlated',
      graph_omission_boundary:
        options.scope === 'cfg'
          ? 'Bounded local CFG export. Use artifact.read for the full graph text.'
          : 'Bounded local call-relationship export. This is not a whole-program call graph.',
      function_name: options.functionName,
      function_address: options.functionAddress,
      ...(options.renderBackend ? { render_backend: options.renderBackend } : {}),
    },
  })
}

export async function renderGraphvizArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dotText: string,
  options: Omit<PersistGraphArtifactOptions, 'format' | 'scope'> & {
    format: Exclude<CFGRenderFormat, 'none'>
    sessionTag?: string | null
  }
): Promise<ArtifactRef> {
  const availability = detectGraphvizAvailability()
  if (!availability.available) {
    throw new Error(availability.error || 'Graphviz dot renderer is unavailable')
  }

  const workspace = await workspaceManager.createWorkspace(options.sampleId)
  const sessionSegment = sanitizeSegment(options.sessionTag || undefined, 'default')
  const reportDir = path.join(workspace.reports, 'graphs', sessionSegment, 'rendered')
  await fs.mkdir(reportDir, { recursive: true })

  const functionSegment = sanitizeSegment(options.functionName || options.functionAddress, 'function')
  const addressSegment = sanitizeSegment(options.functionAddress, 'addr')
  const fileName = `cfg_render_${functionSegment}_${addressSegment}_${Date.now()}.${FILE_EXTENSION_BY_FORMAT[options.format]}`
  const absolutePath = path.join(reportDir, fileName)

  const result = spawnSync('dot', [`-T${options.format}`, '-o', absolutePath], {
    input: dotText,
    encoding: 'utf8',
    timeout: 10000,
    maxBuffer: 8 * 1024 * 1024,
  })

  if (result.error) {
    throw result.error
  }
  if (result.status !== 0) {
    const details = [result.stdout, result.stderr].filter(Boolean).join('\n').trim()
    throw new Error(details || `dot exited with status ${result.status}`)
  }

  const rendered = await fs.readFile(absolutePath)
  const artifactId = randomUUID()
  const createdAt = new Date().toISOString()
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const sha256 = sha256ForContent(rendered)
  const type = GRAPH_ARTIFACT_TYPE_BY_FORMAT[options.format]
  const mime = MIME_BY_FORMAT[options.format]

  database.insertArtifact({
    id: artifactId,
    sample_id: options.sampleId,
    type,
    path: relativePath,
    sha256,
    mime,
    created_at: createdAt,
  })

  return buildArtifactRef({
    id: artifactId,
    type,
    path: relativePath,
    sha256,
    mime,
    metadata: {
      session_tag: options.sessionTag || null,
      artifact_family: 'graphs',
      graph_scope: 'cfg',
      graph_format: options.format,
      graph_surface_role: 'render_export_helper',
      graph_confidence_state: 'observed',
      graph_omission_boundary: 'Rendered export over an already produced DOT graph.',
      function_name: options.functionName,
      function_address: options.functionAddress,
      render_backend: availability.backend,
      renderer_version: availability.version,
    },
  })
}
