/**
 * Frida Script Generator Tests
 * Tasks: dynamic-analysis-automation 5.1-5.4
 */

import { describe, test, expect } from '@jest/globals'
import { generateFridaScript, getAvailableTemplates, getTemplate } from '../../src/frida/script-generator.js'

describe('dynamic-analysis-automation - Frida Script Generator Tests', () => {
  describe('generateFridaScript', () => {
    test('should generate script for process injection capability', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.9, apis: ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'] },
      ]
      
      const script = generateFridaScript(capabilities)
      
      expect(script).toContain('Auto-generated Frida Script')
      expect(script).toContain('process_injection')
      expect(script).toContain('CreateRemoteThread')
      expect(script).toContain('Interceptor.attach')
    })
    
    test('should generate script for crypto capability', () => {
      const capabilities = [
        { name: 'crypto', confidence: 0.85, apis: ['CryptEncrypt', 'CryptDecrypt'] },
      ]
      
      const script = generateFridaScript(capabilities)
      
      expect(script).toContain('crypto')
      expect(script).toContain('CryptEncrypt')
      expect(script).toContain('advapi32.dll')
    })
    
    test('should generate script for multiple capabilities', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.9, apis: ['CreateRemoteThread'] },
        { name: 'crypto', confidence: 0.85, apis: ['CryptEncrypt'] },
        { name: 'persistence', confidence: 0.8, apis: ['RegSetValueExW'] },
      ]
      
      const script = generateFridaScript(capabilities)
      
      expect(script).toContain('process_injection')
      expect(script).toContain('crypto')
      expect(script).toContain('persistence')
    })
    
    test('should skip low-confidence capabilities', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.3, apis: ['CreateRemoteThread'] },
      ]
      
      const script = generateFridaScript(capabilities)
      
      expect(script).not.toContain('CreateRemoteThread')
    })
    
    test('should respect maxApis limit', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.9, apis: Array(100).fill('CreateRemoteThread') },
      ]
      
      const script = generateFridaScript(capabilities, { maxApis: 10 })
      
      const apiCount = (script.match(/CreateRemoteThread/g) || []).length
      expect(apiCount).toBeLessThan(100)
    })
    
    test('should include custom templates', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.9, apis: ['CreateRemoteThread'] },
      ]
      
      const customTemplate = `
// Custom monitoring
console.log("Custom template loaded");
`
      
      const script = generateFridaScript(capabilities, { customTemplates: [customTemplate] })
      
      expect(script).toContain('Custom monitoring')
      expect(script).toContain('Custom template loaded')
    })
    
    test('should generate valid JavaScript syntax', () => {
      const capabilities = [
        { name: 'process_injection', confidence: 0.9, apis: ['CreateRemoteThread'] },
      ]
      
      const script = generateFridaScript(capabilities)
      
      expect(script).toContain('"use strict"')
      expect(script).toContain('rpc.exports')
      expect(script).toContain('Interceptor.attach')
      
      const openBraces = (script.match(/{/g) || []).length
      const closeBraces = (script.match(/}/g) || []).length
      expect(openBraces).toBe(closeBraces)
    })
  })
  
  describe('getAvailableTemplates', () => {
    test('should return list of template names', () => {
      const templates = getAvailableTemplates()
      
      expect(templates).toContain('process_injection')
      expect(templates).toContain('crypto')
      expect(templates).toContain('persistence')
      expect(templates).toContain('network')
    })
  })
  
  describe('getTemplate', () => {
    test('should return template by name', () => {
      const template = getTemplate('process_injection')
      
      expect(template).toBeDefined()
      expect(template).toContain('CreateRemoteThread')
    })
    
    test('should return undefined for unknown template', () => {
      const template = getTemplate('unknown_template')
      
      expect(template).toBeUndefined()
    })
  })
  
  describe('capability mapping', () => {
    test('should map injection variants to process_injection template', () => {
      const capabilities = [
        { name: 'injection', confidence: 0.9, apis: ['CreateRemoteThread'] },
      ]
      
      const script = generateFridaScript(capabilities)
      expect(script).toContain('CreateRemoteThread')
    })
    
    test('should map crypto variants to crypto template', () => {
      const capabilities = [
        { name: 'cryptography', confidence: 0.9, apis: ['CryptEncrypt'] },
      ]
      
      const script = generateFridaScript(capabilities)
      expect(script).toContain('crypto')
    })
    
    test('should map network variants to network template', () => {
      const capabilities = [
        { name: 'c2', confidence: 0.9, apis: ['InternetOpenW'] },
      ]
      
      const script = generateFridaScript(capabilities)
      expect(script).toContain('network')
    })
  })
})
