/**
 * Crypto Flow Generator
 * Tasks: visualization-enhanced-reporting 3.1-3.5
 */

import { ExplanationGraphDigestSchema, type ExplanationGraphDigest } from '../explanation-graphs.js'

export interface CryptoFlowNode {
  id: string
  type: 'algorithm' | 'function' | 'api' | 'data'
  label: string
  algorithm?: string
  isSuspicious: boolean
  confidence_state: 'observed' | 'correlated' | 'inferred'
}
export interface CryptoFlowEdge {
  source: string
  target: string
  label?: string
  type: 'calls' | 'uses' | 'produces'
  confidence_state: 'observed' | 'correlated' | 'inferred'
}
export interface CryptoFlowData {
  nodes: CryptoFlowNode[]
  edges: CryptoFlowEdge[]
  metadata: { sampleId: string; algorithms: string[]; totalNodes: number; confidence: number }
  explanation: ExplanationGraphDigest
}
export interface CryptoFlowOptions { maxNodes?: number; format?: 'dot' | 'mermaid' | 'json'; sampleId?: string }

const CRYPTO_TEMPLATES: Record<string, { apis: string[]; flow: Array<{ from: string; to: string; label: string }> }> = {
  AES: { apis: ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt'], flow: [{ from: 'Key Generation', to: 'Key Schedule', label: 'expand key' }, { from: 'Key Schedule', to: 'Encryption Rounds', label: 'round keys' }, { from: 'Encryption Rounds', to: 'Ciphertext', label: 'output' }] },
  RC4: { apis: ['CryptEncrypt', 'CryptDecrypt', 'RC4', 'ARC4'], flow: [{ from: 'Key Input', to: 'KSA', label: 'initialize' }, { from: 'KSA', to: 'PRGA', label: 'generate keystream' }, { from: 'PRGA', to: 'XOR', label: 'keystream' }, { from: 'Plaintext', to: 'XOR', label: 'input' }, { from: 'XOR', to: 'Ciphertext', label: 'output' }] },
  RSA: { apis: ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt'], flow: [{ from: 'Key Pair Generation', to: 'Public Key', label: 'extract' }, { from: 'Key Pair Generation', to: 'Private Key', label: 'extract' }, { from: 'Public Key', to: 'Encryption', label: 'encrypt' }, { from: 'Private Key', to: 'Decryption', label: 'decrypt' }] },
  Generic: { apis: ['CryptGenKey', 'CryptImportKey', 'CryptExportKey'], flow: [{ from: 'Key Generation', to: 'Encryption', label: 'key' }, { from: 'Plaintext', to: 'Encryption', label: 'input' }, { from: 'Encryption', to: 'Ciphertext', label: 'output' }] },
}

export function generateCryptoFlow(cryptoFindings: Array<{ algorithm?: string; confidence: number; functions?: Array<{ address: string; name: string; apis?: string[] }> }>, options: CryptoFlowOptions = {}): CryptoFlowData {
  const { maxNodes = 20 } = options
  const nodes: CryptoFlowNode[] = []; const edges: CryptoFlowEdge[] = []; const algorithms = new Set<string>()
  
  for (const finding of cryptoFindings.slice(0, maxNodes)) {
    const algorithm = finding.algorithm || 'Generic'
    algorithms.add(algorithm)
    const template = CRYPTO_TEMPLATES[algorithm] || CRYPTO_TEMPLATES.Generic
    const algoNodeId = `algo_${algorithm.toLowerCase()}`
    nodes.push({ id: algoNodeId, type: 'algorithm', label: `${algorithm} Algorithm`, algorithm, isSuspicious: finding.confidence > 0.7, confidence_state: 'correlated' })
    
    for (const step of template.flow) {
      const nodeId = `${algoNodeId}_${step.from.replace(/\s+/g, '_')}`
      if (!nodes.find(n => n.id === nodeId)) nodes.push({ id: nodeId, type: 'function', label: step.from, algorithm, isSuspicious: finding.confidence > 0.7, confidence_state: 'inferred' })
      const targetId = `${algoNodeId}_${step.to.replace(/\s+/g, '_')}`
      if (!nodes.find(n => n.id === targetId)) nodes.push({ id: targetId, type: 'function', label: step.to, algorithm, isSuspicious: finding.confidence > 0.7, confidence_state: 'inferred' })
      edges.push({ source: nodeId, target: targetId, label: step.label, type: 'uses', confidence_state: 'inferred' })
    }
  }

  const confidence =
    cryptoFindings.length > 0 ? cryptoFindings.reduce((sum, f) => sum + f.confidence, 0) / cryptoFindings.length : 0
  const explanation = ExplanationGraphDigestSchema.parse({
    graph_type: 'crypto_flow',
    surface_role: 'explanation_artifact',
    title: 'Crypto Explanation Flow',
    semantic_summary:
      cryptoFindings.length > 0
        ? `Template-backed crypto explanation for ${Array.from(algorithms).join(', ')}. Treat this as a bounded reasoning aid derived from crypto findings, not as a full observed execution trace.`
        : 'No crypto findings were available to derive a crypto explanation graph.',
    confidence_state: cryptoFindings.some((item) => item.confidence >= 0.85) ? 'correlated' : 'inferred',
    confidence_states_present: ['correlated', 'inferred'],
    confidence_score: confidence,
    node_count: nodes.length,
    edge_count: edges.length,
    bounded: true,
    available_serializers: ['json', 'dot', 'mermaid'],
    provenance: [
      {
        kind: 'artifact',
        label: 'crypto_identification',
        detail: 'Derived from persisted or explicitly supplied crypto-identification findings.',
      },
      {
        kind: 'heuristic',
        label: 'algorithm_templates',
        detail: 'Flow edges are template-driven and should be treated as inferred structure unless separately observed at runtime.',
      },
    ],
    omissions: [
      {
        code: 'template_driven_flow',
        reason: 'The graph emphasizes bounded algorithm flow explanation and omits low-level block-by-block implementation detail.',
      },
      ...(cryptoFindings.length > maxNodes
        ? [
            {
              code: 'bounded_crypto_selection',
              reason: `Omitted ${cryptoFindings.length - maxNodes} lower-priority crypto finding(s) to keep the explanation compact.`,
            },
          ]
        : []),
    ],
    recommended_next_tools: ['breakpoint.smart', 'trace.condition', 'workflow.analyze.promote'],
  })

  return {
    nodes,
    edges,
    metadata: {
      sampleId: options.sampleId || '',
      algorithms: Array.from(algorithms),
      totalNodes: nodes.length,
      confidence,
    },
    explanation,
  }
}

export function cryptoFlowToDot(data: CryptoFlowData, options?: { title?: string }): string {
  const { title = 'Crypto Algorithm Flow' } = options || {}
  let dot = `digraph "${title}" {\n  rankdir=TB;\n  node [shape=box, style=rounded];\n\n`
  for (const node of data.nodes) {
    let shape = 'box', color = 'black', fillcolor = 'white', style = 'solid'
    if (node.type === 'algorithm') { shape = 'hexagon'; fillcolor = 'lightyellow'; style = 'filled,bold' }
    else if (node.type === 'api') { shape = 'ellipse'; fillcolor = 'lightgreen'; style = 'filled' }
    else if (node.type === 'data') { shape = 'cylinder'; fillcolor = 'lightgray'; style = 'filled' }
    if (node.isSuspicious) { color = 'red'; style = style.includes('filled') ? `${style},bold` : 'filled,bold' }
    dot += `  "${node.id}" [label="${escapeDot(node.label)}", shape="${shape}", color="${color}", style="${style}", fillcolor="${fillcolor}"];\n`
  }
  dot += '\n'
  for (const edge of data.edges) {
    let color = 'gray', style = 'solid'
    if (edge.type === 'calls') { color = 'blue'; style = 'dashed' }
    dot += `  "${edge.source}" -> "${edge.target}" [label="${escapeDot(edge.label || '')}", color="${color}", style="${style}"];\n`
  }
  return dot + '}\n'
}

export function cryptoFlowToMermaid(data: CryptoFlowData): string {
  let mermaid = 'graph TB\n'
  for (const node of data.nodes) {
    let shape = '["', endShape = '"]'
    if (node.type === 'algorithm') { shape = '{{'; endShape = '}}' }
    else if (node.type === 'api') { shape = '(('; endShape = '))' }
    else if (node.type === 'data') { shape = '[('; endShape = ')]' }
    mermaid += `  ${node.id}${shape}${escapeMermaid(node.label)}${endShape}\n`
    if (node.isSuspicious) mermaid += `  ${node.id}:::suspicious\n`
  }
  mermaid += '\n'
  for (const edge of data.edges) mermaid += `  ${edge.source} -->|${escapeMermaid(edge.label || '')}| ${edge.target}\n`
  return mermaid + '\nclassDef suspicious fill:#ffcccc,stroke:red,stroke-width:2px;\nclassDef algorithm fill:lightyellow,stroke:orange,stroke-width:2px;\nclassDef api fill:lightgreen,stroke:green;\nclassDef data fill:lightgray,stroke:gray;\n'
}

function escapeDot(text: string): string { return text.replace(/"/g, '\\"').replace(/\n/g, '\\n') }
function escapeMermaid(text: string): string { return text.replace(/"/g, "'").replace(/\n/g, ' ') }
