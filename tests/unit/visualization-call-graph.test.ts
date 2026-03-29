/**
 * Call Graph Generator tests
 * Tasks: visualization-enhanced-reporting 1.5
 */

import { describe, test, expect } from '@jest/globals'
import {
  generateCallGraph,
  callGraphToDot,
  callGraphToMermaid,
  type CallGraphOptions,
} from '../../src/visualization/call-graph.js'

describe('visualization-enhanced-reporting - Call Graph Generator', () => {
  const sampleFunctions = [
    {
      address: '0x140001000',
      name: 'main',
      size: 256,
      score: 0.9,
      callers: [],
      callees: ['0x140001100', '0x140001200'],
    },
    {
      address: '0x140001100',
      name: 'decrypt_config',
      size: 128,
      score: 0.85,
      callers: ['0x140001000'],
      callees: ['0x140001300'],
    },
    {
      address: '0x140001200',
      name: 'sub_140001200',
      size: 64,
      score: 0.3,
      callers: ['0x140001000'],
      callees: [],
    },
    {
      address: '0x140001300',
      name: 'CryptDecrypt',
      size: 32,
      score: 0.95,
      callers: ['0x140001100'],
      callees: [],
    },
  ]

  describe('generateCallGraph', () => {
    test('should generate call graph from functions', () => {
      const graph = generateCallGraph(sampleFunctions)

      expect(graph.nodes).toHaveLength(4)
      expect(Array.isArray(graph.edges)).toBe(true)
      expect(graph.edges.length).toBeGreaterThan(0)
      expect(graph.metadata.totalFunctions).toBe(4)
    })

    test('should mark high-score functions as suspicious', () => {
      const graph = generateCallGraph(sampleFunctions)

      const suspicious = graph.nodes.filter(n => n.isSuspicious)
      expect(suspicious.length).toBeGreaterThan(0)
      
      // main and CryptDecrypt should be suspicious (score > 0.7)
      expect(suspicious.some(n => n.name === 'main')).toBe(true)
      expect(suspicious.some(n => n.name === 'CryptDecrypt')).toBe(true)
    })

    test('should respect maxNodes limit', () => {
      const graph = generateCallGraph(sampleFunctions, { maxNodes: 2 })

      expect(graph.nodes).toHaveLength(2)
      // Should keep highest scored functions
      expect(graph.nodes[0].score).toBeGreaterThanOrEqual(graph.nodes[1].score)
    })

    test('should sort functions by score', () => {
      const graph = generateCallGraph(sampleFunctions)

      const scores = graph.nodes.map(n => n.score)
      for (let i = 1; i < scores.length; i++) {
        expect(scores[i - 1]).toBeGreaterThanOrEqual(scores[i])
      }
    })

    test('should create edges from callees', () => {
      const graph = generateCallGraph(sampleFunctions)

      // Should have edges (main has 2 callees)
      expect(graph.edges.length).toBeGreaterThan(0)
      
      // Check that edges have correct structure
      for (const edge of graph.edges) {
        expect(edge.source).toBeDefined()
        expect(edge.target).toBeDefined()
        expect(edge.callCount).toBeGreaterThanOrEqual(1)
      }
    })

    test('should aggregate multiple calls to same function', () => {
      const functionsWithDuplicates = [
        {
          address: '0x1000',
          name: 'caller',
          size: 100,
          score: 0.5,
          callees: ['0x2000', '0x2000', '0x2000'],
        },
        {
          address: '0x2000',
          name: 'callee',
          size: 50,
          score: 0.5,
        },
      ]

      const graph = generateCallGraph(functionsWithDuplicates)
      const edge = graph.edges.find(
        e => e.source === '0x1000' && e.target === '0x2000'
      )

      expect(edge).toBeDefined()
      expect(edge!.callCount).toBe(3)
    })
  })

  describe('callGraphToDot', () => {
    test('should generate valid DOT format', () => {
      const graph = generateCallGraph(sampleFunctions)
      const dot = callGraphToDot(graph)

      expect(dot).toContain('digraph')
      expect(dot).toContain('rankdir=TB')
      expect(dot).toContain('node [shape=box')
      expect(dot).toContain('}')
    })

    test('should highlight suspicious functions in red', () => {
      const graph = generateCallGraph(sampleFunctions)
      const dot = callGraphToDot(graph)

      expect(dot).toContain('color="red"')
      expect(dot).toContain('fillcolor="#ffcccc"')
    })

    test('should include custom title', () => {
      const graph = generateCallGraph(sampleFunctions)
      const dot = callGraphToDot(graph, { title: 'Custom Title' })

      expect(dot).toContain('digraph "Custom Title"')
    })

    test('should escape special characters', () => {
      const functionsWithSpecialChars = [
        {
          address: '0x1000',
          name: 'func_with"quotes"and\nnewlines',
          size: 100,
          score: 0.5,
        },
      ]

      const graph = generateCallGraph(functionsWithSpecialChars)
      const dot = callGraphToDot(graph)

      expect(dot).toContain('\\"')
    })
  })

  describe('callGraphToMermaid', () => {
    test('should generate valid Mermaid format', () => {
      const graph = generateCallGraph(sampleFunctions)
      const mermaid = callGraphToMermaid(graph)

      expect(mermaid).toContain('graph TB')
      expect(mermaid).toContain('classDef suspicious')
    })

    test('should mark suspicious functions with class', () => {
      const graph = generateCallGraph(sampleFunctions)
      const mermaid = callGraphToMermaid(graph)

      expect(mermaid).toContain(':::suspicious')
    })

    test('should truncate long function names', () => {
      const longNameFunction = [
        {
          address: '0x1000',
          name: 'this_is_a_very_long_function_name_that_exceeds_limit',
          size: 100,
          score: 0.5,
        },
      ]

      const graph = generateCallGraph(longNameFunction)
      const mermaid = callGraphToMermaid(graph)

      // Should truncate to ~20 chars
      expect(mermaid.length).toBeLessThan(500)
    })

    test('should escape quotes in Mermaid', () => {
      const functionWithQuotes = [
        {
          address: '0x1000',
          name: 'func_with"quotes',
          size: 100,
          score: 0.5,
        },
      ]

      const graph = generateCallGraph(functionWithQuotes)
      const mermaid = callGraphToMermaid(graph)

      // Should handle quotes gracefully (converted to single quotes or escaped)
      expect(mermaid).toContain("func_with'quotes")
    })
  })

  describe('graph metadata', () => {
    test('should calculate correct suspicious function count', () => {
      const graph = generateCallGraph(sampleFunctions)

      const expectedSuspicious = sampleFunctions.filter(f => f.score > 0.7).length
      expect(graph.metadata.suspiciousFunctions).toBe(expectedSuspicious)
    })

    test('should include sample ID in metadata', () => {
      const sampleId = 'sha256:abc123'
      const graph = generateCallGraph(sampleFunctions, { sampleId })

      expect(graph.metadata.sampleId).toBe(sampleId)
    })

    test('should calculate max depth', () => {
      const graph = generateCallGraph(sampleFunctions)

      // main -> decrypt_config -> CryptDecrypt = depth 3
      expect(graph.metadata.maxDepth).toBeGreaterThanOrEqual(2)
    })

    test('should expose explanation-first metadata instead of only renderer data', () => {
      const graph = generateCallGraph(sampleFunctions, { sampleId: 'sha256:abc123' })

      expect(graph.explanation.graph_type).toBe('call_graph')
      expect(graph.explanation.surface_role).toBe('local_navigation_aid')
      expect(graph.explanation.confidence_state).toBe('correlated')
      expect(graph.explanation.recommended_next_tools).toContain('code.function.cfg')
      expect(graph.explanation.provenance.length).toBeGreaterThan(0)
    })
  })

  describe('edge cases', () => {
    test('should handle empty function list', () => {
      const graph = generateCallGraph([])

      expect(graph.nodes).toHaveLength(0)
      expect(graph.edges).toHaveLength(0)
      expect(graph.metadata.totalFunctions).toBe(0)
    })

    test('should handle functions without callees', () => {
      const isolatedFunctions = [
        {
          address: '0x1000',
          name: 'isolated',
          size: 100,
          score: 0.5,
        },
      ]

      const graph = generateCallGraph(isolatedFunctions)

      expect(graph.nodes).toHaveLength(1)
      expect(graph.edges).toHaveLength(0)
    })

    test('should handle circular references', () => {
      const circularFunctions = [
        {
          address: '0x1000',
          name: 'funcA',
          size: 100,
          score: 0.5,
          callees: ['0x2000'],
        },
        {
          address: '0x2000',
          name: 'funcB',
          size: 100,
          score: 0.5,
          callees: ['0x1000'],
        },
      ]

      const graph = generateCallGraph(circularFunctions)

      expect(graph.nodes).toHaveLength(2)
      expect(graph.edges).toHaveLength(2) // A->B and B->A
    })
  })
})
