/**
 * Visualization Integration for Reports
 * Tasks: visualization-enhanced-reporting 4.1-4.6
 */

import { generateCallGraph, callGraphToDot, callGraphToMermaid } from './call-graph.js'
import { generateDataFlow, dataFlowToDot, dataFlowToMermaid } from './data-flow.js'
import { generateCryptoFlow, cryptoFlowToDot, cryptoFlowToMermaid } from './crypto-flow.js'
import type { ExplanationGraphDigest } from '../explanation-graphs.js'

export interface VisualizationOptions { includeCallGraph?: boolean; includeDataFlow?: boolean; includeCryptoFlow?: boolean; format?: 'markdown' | 'html'; sampleId?: string }
export interface VisualizationResult {
  callGraph?: { dot: string; mermaid: string; metadata: any; explanation: ExplanationGraphDigest }
  dataFlow?: { dot: string; mermaid: string; metadata: any; explanation: ExplanationGraphDigest }
  cryptoFlow?: { dot: string; mermaid: string; metadata: any; explanation: ExplanationGraphDigest }
}

export function generateReportVisualizations(
  functions: Array<{ address: string; name: string; size: number; score: number; callers?: string[]; callees?: string[]; calledApis?: string[]; referencedStrings?: string[] }>,
  cryptoFindings?: Array<{ algorithm?: string; confidence: number; functions?: Array<{ address: string; name: string; apis?: string[] }> }>,
  options: VisualizationOptions = {}
): VisualizationResult {
  const result: VisualizationResult = {}
  if (options.includeCallGraph !== false) {
    const callGraphData = generateCallGraph(functions, { sampleId: options.sampleId })
    result.callGraph = { dot: callGraphToDot(callGraphData, { title: `Call Graph - ${options.sampleId?.substring(0, 16) || 'Sample'}` }), mermaid: callGraphToMermaid(callGraphData), metadata: callGraphData.metadata, explanation: callGraphData.explanation }
  }
  if (options.includeDataFlow !== false) {
    const dataFlowData = generateDataFlow(functions, { sampleId: options.sampleId })
    result.dataFlow = { dot: dataFlowToDot(dataFlowData, { title: `Data Flow - ${options.sampleId?.substring(0, 16) || 'Sample'}` }), mermaid: dataFlowToMermaid(dataFlowData), metadata: dataFlowData.metadata, explanation: dataFlowData.explanation }
  }
  if (options.includeCryptoFlow !== false && cryptoFindings && cryptoFindings.length > 0) {
    const cryptoFlowData = generateCryptoFlow(cryptoFindings, { sampleId: options.sampleId })
    result.cryptoFlow = { dot: cryptoFlowToDot(cryptoFlowData, { title: `Crypto Flow - ${options.sampleId?.substring(0, 16) || 'Sample'}` }), mermaid: cryptoFlowToMermaid(cryptoFlowData), metadata: cryptoFlowData.metadata, explanation: cryptoFlowData.explanation }
  }
  return result
}

export function renderVisualizationsAsMarkdown(visualizations: VisualizationResult): string {
  let markdown = ''
  if (visualizations.callGraph) { markdown += '## Call Graph\n\n' + `${visualizations.callGraph.explanation.semantic_summary}\n\n` + '```mermaid\n' + visualizations.callGraph.mermaid + '\n```\n\n' + `**Role**: ${visualizations.callGraph.explanation.surface_role}\n**Confidence State**: ${visualizations.callGraph.explanation.confidence_state}\n\n` }
  if (visualizations.dataFlow) { markdown += '## Data Flow\n\n' + `${visualizations.dataFlow.explanation.semantic_summary}\n\n` + '```mermaid\n' + visualizations.dataFlow.mermaid + '\n```\n\n' + `**Role**: ${visualizations.dataFlow.explanation.surface_role}\n**Confidence States**: ${visualizations.dataFlow.explanation.confidence_states_present.join(', ')}\n\n` }
  if (visualizations.cryptoFlow) { markdown += '## Crypto Algorithm Flow\n\n' + `${visualizations.cryptoFlow.explanation.semantic_summary}\n\n` + '```mermaid\n' + visualizations.cryptoFlow.mermaid + '\n```\n\n' + `**Algorithms**: ${visualizations.cryptoFlow.metadata.algorithms.join(', ')}\n**Confidence State**: ${visualizations.cryptoFlow.explanation.confidence_state}\n\n` }
  return markdown
}

export function renderVisualizationsAsHtml(visualizations: VisualizationResult): string {
  let html = ''
  if (visualizations.callGraph) { html += '<h2>Call Graph</h2>\n' + `<p>${visualizations.callGraph.explanation.semantic_summary}</p>\n` + '<div class="mermaid">\n' + visualizations.callGraph.mermaid + '\n</div>\n' + `<p><strong>Role</strong>: ${visualizations.callGraph.explanation.surface_role}</p>\n` }
  if (visualizations.dataFlow) { html += '<h2>Data Flow</h2>\n' + `<p>${visualizations.dataFlow.explanation.semantic_summary}</p>\n` + '<div class="mermaid">\n' + visualizations.dataFlow.mermaid + '\n</div>\n' + `<p><strong>Confidence States</strong>: ${visualizations.dataFlow.explanation.confidence_states_present.join(', ')}</p>\n` }
  if (visualizations.cryptoFlow) { html += '<h2>Crypto Algorithm Flow</h2>\n' + `<p>${visualizations.cryptoFlow.explanation.semantic_summary}</p>\n` + '<div class="mermaid">\n' + visualizations.cryptoFlow.mermaid + '\n</div>\n' + `<p><strong>Confidence State</strong>: ${visualizations.cryptoFlow.explanation.confidence_state}</p>\n` }
  return html
}
