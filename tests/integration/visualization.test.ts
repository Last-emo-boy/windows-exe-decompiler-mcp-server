/**
 * Visualization Tests
 * Tasks: visualization-enhanced-reporting 6.1-6.5
 */

import { describe, test, expect } from '@jest/globals'
import { generateCallGraph, callGraphToDot, callGraphToMermaid } from '../../src/visualization/call-graph.js'
import { generateDataFlow, dataFlowToDot, dataFlowToMermaid } from '../../src/visualization/data-flow.js'
import { generateCryptoFlow, cryptoFlowToDot, cryptoFlowToMermaid } from '../../src/visualization/crypto-flow.js'

describe('visualization-enhanced-reporting - Visualization Tests', () => {
  const sampleFunctions = [
    { address: '0x140001000', name: 'main', size: 256, score: 0.9, callers: [], callees: ['0x140001100', '0x140001200'] },
    { address: '0x140001100', name: 'decrypt_config', size: 128, score: 0.85, callers: ['0x140001000'], callees: ['0x140001300'] },
    { address: '0x140001200', name: 'sub_140001200', size: 64, score: 0.3, callers: ['0x140001000'], callees: [] },
    { address: '0x140001300', name: 'CryptDecrypt', size: 32, score: 0.95, callers: ['0x140001100'], callees: [] },
  ]
  
  describe('Call Graph Generation', () => {
    test('should generate call graph from functions', () => {
      const graph = generateCallGraph(sampleFunctions)
      
      expect(graph.nodes).toHaveLength(4)
      expect(graph.edges.length).toBeGreaterThan(0)
      expect(graph.metadata.totalFunctions).toBe(4)
    })
    
    test('should mark high-score functions as suspicious', () => {
      const graph = generateCallGraph(sampleFunctions)
      const suspicious = graph.nodes.filter(n => n.isSuspicious)
      
      expect(suspicious.length).toBeGreaterThan(0)
      expect(suspicious.some(n => n.name === 'main')).toBe(true)
      expect(suspicious.some(n => n.name === 'CryptDecrypt')).toBe(true)
    })
    
    test('should generate valid DOT format', () => {
      const graph = generateCallGraph(sampleFunctions)
      const dot = callGraphToDot(graph)
      
      expect(dot).toContain('digraph')
      expect(dot).toContain('rankdir=TB')
      expect(dot).toContain('}')
    })
    
    test('should generate valid Mermaid format', () => {
      const graph = generateCallGraph(sampleFunctions)
      const mermaid = callGraphToMermaid(graph)
      
      expect(mermaid).toContain('graph TB')
      expect(mermaid).toContain('classDef suspicious')
    })
  })
  
  describe('Data Flow Generation', () => {
    test('should generate data flow from functions', () => {
      const functions = [
        { address: '0x1000', name: 'func1', score: 0.8, calledApis: ['CryptEncrypt', 'VirtualAlloc'], referencedStrings: ['password'] },
        { address: '0x2000', name: 'func2', score: 0.6, calledApis: ['WriteFile', 'send'], referencedStrings: ['config'] },
      ]
      
      const dataFlow = generateDataFlow(functions)
      
      expect(dataFlow.nodes.length).toBeGreaterThan(0)
      expect(dataFlow.metadata.dataSources).toBeGreaterThan(0)
      expect(dataFlow.metadata.dataSinks).toBeGreaterThan(0)
    })
    
    test('should track crypto keys', () => {
      const functions = [
        { address: '0x1000', name: 'crypto_func', score: 0.9, calledApis: ['CryptEncrypt', 'CryptDecrypt'], referencedStrings: [] },
      ]
      
      const dataFlow = generateDataFlow(functions, { trackDataTypes: ['crypto_keys'] })
      
      const cryptoSources = dataFlow.nodes.filter(n => n.type === 'data_source' && n.dataType === 'crypto_keys')
      expect(cryptoSources.length).toBeGreaterThan(0)
    })
    
    test('should generate DOT and Mermaid formats', () => {
      const functions = [
        { address: '0x1000', name: 'func1', score: 0.8, calledApis: ['CryptEncrypt'], referencedStrings: [] },
      ]
      
      const dataFlow = generateDataFlow(functions)
      
      const dot = dataFlowToDot(dataFlow)
      expect(dot).toContain('digraph')
      
      const mermaid = dataFlowToMermaid(dataFlow)
      expect(mermaid).toContain('graph LR')
    })
  })
  
  describe('Crypto Flow Generation', () => {
    test('should generate crypto flow from findings', () => {
      const cryptoFindings = [
        { algorithm: 'AES', confidence: 0.9, functions: [{ address: '0x1000', name: 'aes_encrypt', apis: ['CryptEncrypt'] }] },
      ]
      
      const cryptoFlow = generateCryptoFlow(cryptoFindings)
      
      expect(cryptoFlow.metadata.algorithms).toContain('AES')
      expect(cryptoFlow.nodes.length).toBeGreaterThan(0)
      expect(cryptoFlow.metadata.confidence).toBe(0.9)
    })
    
    test('should use generic template for unknown algorithms', () => {
      const cryptoFindings = [
        { algorithm: 'UnknownAlgo', confidence: 0.7, functions: [] },
      ]
      
      const cryptoFlow = generateCryptoFlow(cryptoFindings)
      
      expect(cryptoFlow.metadata.algorithms).toContain('UnknownAlgo')
      expect(cryptoFlow.nodes.length).toBeGreaterThan(0)
    })
    
    test('should generate DOT and Mermaid formats', () => {
      const cryptoFindings = [
        { algorithm: 'AES', confidence: 0.9, functions: [] },
      ]
      
      const cryptoFlow = generateCryptoFlow(cryptoFindings)
      
      const dot = cryptoFlowToDot(cryptoFlow)
      expect(dot).toContain('digraph')
      
      const mermaid = cryptoFlowToMermaid(cryptoFlow)
      expect(mermaid).toContain('graph TB')
    })
  })
  
  describe('Edge Cases', () => {
    test('should handle empty function list', () => {
      const graph = generateCallGraph([])
      expect(graph.nodes).toHaveLength(0)
      expect(graph.edges).toHaveLength(0)
    })
    
    test('should handle functions without callees', () => {
      const functions = [{ address: '0x1000', name: 'isolated', size: 100, score: 0.5 }]
      const graph = generateCallGraph(functions)
      expect(graph.nodes).toHaveLength(1)
      expect(graph.edges).toHaveLength(0)
    })
    
    test('should respect maxNodes limit', () => {
      const manyFunctions = Array(100).fill(null).map((_, i) => ({
        address: `0x${i.toString(16)}`,
        name: `func_${i}`,
        size: 100,
        score: 0.5,
      }))
      
      const graph = generateCallGraph(manyFunctions, { maxNodes: 10 })
      expect(graph.nodes).toHaveLength(10)
    })
  })
})
