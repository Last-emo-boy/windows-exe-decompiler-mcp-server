/**
 * Knowledge Base Integration Tests
 * Tasks: collaborative-knowledge-base 7.1-7.4
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { DatabaseManager } from '../../src/database.js'
import { initializeKnowledgeBase, getKbStats } from '../../src/kb/kb-database.js'
import { contributeFunction } from '../../src/kb/function-kb.js'
import { searchFunctions } from '../../src/kb/search-kb.js'
import { linkSampleToThreat, getSampleThreatLinks } from '../../src/kb/sample-kb.js'

describe('collaborative-knowledge-base - Integration Tests', () => {
  let db: DatabaseManager
  
  beforeEach(() => {
    db = new DatabaseManager(':memory:')
    initializeKnowledgeBase(db)
  })
  
  afterEach(() => {
    db.close()
  })
  
  describe('KB Database', () => {
    test('should initialize KB tables', () => {
      const stats = getKbStats(db)
      expect(stats.totalFunctions).toBe(0)
      expect(stats.totalSamples).toBe(0)
      expect(stats.totalIndexEntries).toBe(0)
    })
  })
  
  describe('Function KB', () => {
    test('should contribute and search functions', async () => {
      const id = await contributeFunction(db, {
        address: '0x140001000',
        name: 'decrypt_config',
        explanation: 'Decrypts configuration data using AES',
        behavior: 'decrypt_config',
        features: {
          apis: ['CryptDecrypt', 'CryptImportKey'],
          strings: ['config', 'password'],
          cfg_shape: 'hash123',
        },
        source: 'llm',
        sampleId: 'sha256:abc123',
      })
      
      expect(id).toBeDefined()
      
      const results = searchFunctions(db, { apis: ['CryptDecrypt'], minConfidence: 0.5 })
      expect(results.total).toBeGreaterThan(0)
      expect(results.results[0].name).toBe('decrypt_config')
    })
    
    test('should rank by confidence', async () => {
      await contributeFunction(db, {
        address: '0x1000',
        name: 'auto_func',
        explanation: 'Auto extracted',
        behavior: 'test',
        features: { apis: ['CreateFile'], strings: [], cfg_shape: 'hash' },
        source: 'auto',
        sampleId: 'sha256:abc',
      })
      
      await contributeFunction(db, {
        address: '0x2000',
        name: 'human_func',
        explanation: 'Human verified',
        behavior: 'test',
        features: { apis: ['CreateFile'], strings: [], cfg_shape: 'hash' },
        source: 'human',
        sampleId: 'sha256:def',
      })
      
      const results = searchFunctions(db, { apis: ['CreateFile'] })
      expect(results.results[0].name).toBe('human_func')
      expect(results.results[0].confidence).toBeGreaterThan(0.8)
    })
    
    test('should search by behavior', async () => {
      await contributeFunction(db, {
        address: '0x1000',
        name: 'func1',
        explanation: 'Test',
        behavior: 'decrypt_data',
        features: { apis: [], strings: [], cfg_shape: 'hash' },
        source: 'llm',
        sampleId: 'sha256:abc',
      })
      
      const results = searchFunctions(db, { behavior: 'decrypt' })
      expect(results.total).toBe(1)
      expect(results.results[0].behavior).toBe('decrypt_data')
    })
  })
  
  describe('Sample KB', () => {
    test('should link sample to threat intel', async () => {
      const id = await linkSampleToThreat(db, {
        sampleId: 'sha256:malware123',
        family: 'Emotet',
        campaign: 'Campaign-A',
        tags: ['banking', 'trojan'],
        attribution: 'ThreatActor-A',
      })
      
      expect(id).toBeDefined()
      
      const links = getSampleThreatLinks(db, 'sha256:malware123')
      expect(links).not.toBeNull()
      expect(links?.family).toBe('Emotet')
      expect(links?.tags).toContain('banking')
    })
    
    test('should search samples by family', () => {
      linkSampleToThreat(db, {
        sampleId: 'sha256:sample1',
        family: 'Emotet',
        tags: ['banking'],
      })
      
      linkSampleToThreat(db, {
        sampleId: 'sha256:sample2',
        family: 'TrickBot',
        tags: ['banking'],
      })
      
      const results = db.querySql<any>('SELECT * FROM sample_kb WHERE threat_intel_family LIKE ?', ['%Emotet%'])
      expect(results.length).toBe(1)
      expect(results[0].sample_id).toBe('sha256:sample1')
    })
  })
  
  describe('Performance Test (100+ entries)', () => {
    test('should handle 100+ entries efficiently', async () => {
      const contributePromises = []
      for (let i = 0; i < 100; i++) {
        contributePromises.push(contributeFunction(db, {
          address: `0x${i.toString(16).padStart(4, '0')}`,
          name: `func_${i}`,
          explanation: `Test function ${i}`,
          behavior: 'test',
          features: {
            apis: [`Api${i % 10}`],
            strings: [`str${i % 20}`],
            cfg_shape: `hash${i % 5}`,
          },
          source: i % 3 === 0 ? 'human' : i % 3 === 1 ? 'llm' : 'auto',
          sampleId: `sha256:abc${i}`,
        }))
      }
      
      await Promise.all(contributePromises)
      
      const stats = getKbStats(db)
      expect(stats.totalFunctions).toBe(100)
      
      const startTime = Date.now()
      const results = searchFunctions(db, { apis: ['Api1'], limit: 50 })
      const searchTime = Date.now() - startTime
      
      expect(searchTime).toBeLessThan(100)
      expect(results.total).toBeGreaterThan(0)
    })
  })
})
