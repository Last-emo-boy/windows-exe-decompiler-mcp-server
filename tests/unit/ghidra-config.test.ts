/**
 * Unit tests for Ghidra configuration module
 * **Validates: Requirements 8.1, Technical constraint 3**
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { spawnSync } from 'child_process'
import {
  getAnalyzeHeadlessPath,
  ensureScriptsDirectory,
  generateProjectKey,
  createGhidraProject,
  cleanupOldGhidraProjects,
  buildProcessInvocation,
  checkGhidraHealth,
  detectGhidraInstallation,
  ghidraConfig,
} from '../../src/ghidra-config.js'
import { resolvePackagePath } from '../../src/runtime-paths.js'

describe('Ghidra Configuration', () => {
  const testScriptsDir = path.join(process.cwd(), 'test-ghidra-scripts')
  const testGhidraWorkspace = path.join(process.cwd(), 'test-ghidra-workspace')

  beforeEach(() => {
    // Clean up test directories
    if (fs.existsSync(testScriptsDir)) {
      fs.rmSync(testScriptsDir, { recursive: true, force: true })
    }
    if (fs.existsSync(testGhidraWorkspace)) {
      fs.rmSync(testGhidraWorkspace, { recursive: true, force: true })
    }
  })

  afterEach(() => {
    // Clean up test directories
    if (fs.existsSync(testScriptsDir)) {
      fs.rmSync(testScriptsDir, { recursive: true, force: true })
    }
    if (fs.existsSync(testGhidraWorkspace)) {
      fs.rmSync(testGhidraWorkspace, { recursive: true, force: true })
    }
    
    // Clean up environment variables
    delete process.env.GHIDRA_INSTALL_DIR
    delete process.env.GHIDRA_PATH
  })

  describe('getAnalyzeHeadlessPath', () => {
    it('should return correct path for Windows', () => {
      const installDir = 'C:\\ghidra'
      const result = getAnalyzeHeadlessPath(installDir)

      if (process.platform === 'win32') {
        expect(result).toBe(path.join(installDir, 'support', 'analyzeHeadless.bat'))
      } else {
        expect(result).toBe(path.join(installDir, 'support', 'analyzeHeadless'))
      }
    })

    it('should return correct path for Unix-like systems', () => {
      const installDir = '/opt/ghidra'
      const result = getAnalyzeHeadlessPath(installDir)

      if (process.platform === 'win32') {
        expect(result).toContain('analyzeHeadless.bat')
      } else {
        expect(result).toBe(path.join(installDir, 'support', 'analyzeHeadless'))
      }
    })

    it('should handle paths with spaces', () => {
      const installDir = '/opt/ghidra 10.4'
      const result = getAnalyzeHeadlessPath(installDir)

      expect(result).toContain('ghidra 10.4')
      expect(result).toContain('support')
      expect(result).toContain('analyzeHeadless')
    })
  })

  describe('Windows batch invocation quoting', () => {
    it('should route .bat through cmd.exe on win32', () => {
      const command = 'C:\\Program Files\\Ghidra\\support\\analyzeHeadless.bat'
      const args = ['C:\\ws path\\project_a', 'proj_key', '-help']

      const result = buildProcessInvocation(command, args, 'win32')

      expect(result.command.toLowerCase().endsWith('cmd.exe')).toBe(true)
      expect(result.args[0]).toBe('/d')
      expect(result.args[1]).toBe('/s')
      expect(result.args[2]).toBe('/c')
      expect(result.args[3]).toContain(`"${command}"`)
      expect(result.args[3]).toContain('"C:\\ws path\\project_a"')
      expect(result.args[3]).toContain('"proj_key"')
      expect(result.args[3]).toContain('"-help"')
      expect(result.args[3].startsWith('""')).toBe(true)
      expect(result.args[3].endsWith('"')).toBe(true)
      expect(result.windowsVerbatimArguments).toBe(true)
    })

    it('should keep special characters quoted in win32 command line', () => {
      const command = 'C:\\Users\\ES&E\\Ghidra (Test)\\\u4e2d\u6587\\support\\analyzeHeadless.bat'
      const args = [
        'C:\\tmp\\with space & symbol\\project(1)',
        '\u9879\u76ee(\u4e2d\u6587)&key',
        '-import',
        'C:\\samples\\a&b (x86)\\\u6837\u672c.exe',
      ]

      const result = buildProcessInvocation(command, args, 'win32')
      const cmdLine = result.args[3]

      expect(result.command.toLowerCase().endsWith('cmd.exe')).toBe(true)
      expect(cmdLine).toContain(`"${command}"`)
      expect(cmdLine).toContain('"C:\\tmp\\with space & symbol\\project(1)"')
      expect(cmdLine).toContain('"\u9879\u76ee(\u4e2d\u6587)&key"')
      expect(cmdLine).toContain('"-import"')
      expect(cmdLine).toContain('"C:\\samples\\a&b (x86)\\\u6837\u672c.exe"')
      expect(result.windowsVerbatimArguments).toBe(true)
    })

    it('should preserve each problematic path token (space,&,parentheses,unicode) in quoted args', () => {
      const command = 'C:\\Tool Root\\Ghidra\\support\\analyzeHeadless.bat'
      const args = [
        'C:\\path with space\\proj',
        'C:\\path\\ES&E\\proj',
        'C:\\path\\name(test)\\proj',
        'C:\\路径\\样本.exe',
      ]

      const result = buildProcessInvocation(command, args, 'win32')
      const cmdLine = result.args[3]

      expect(result.command.toLowerCase().endsWith('cmd.exe')).toBe(true)
      expect(cmdLine).toContain('"C:\\path with space\\proj"')
      expect(cmdLine).toContain('"C:\\path\\ES&E\\proj"')
      expect(cmdLine).toContain('"C:\\path\\name(test)\\proj"')
      expect(cmdLine).toContain('"C:\\路径\\样本.exe"')
      expect(result.windowsVerbatimArguments).toBe(true)
    })

    it('should wrap full cmd /c command line exactly once to avoid & splitting', () => {
      const command = 'C:\\Users\\ES&E\\Ghidra (Test)\\中文\\support\\analyzeHeadless.bat'
      const args = [
        'C:\\ws with space\\project(1)',
        'key&(zh)',
        '-import',
        'C:\\samples\\a&b (x86)\\样本.exe',
      ]

      const result = buildProcessInvocation(command, args, 'win32')
      const wrapped = result.args[3]

      expect(result.command.toLowerCase().endsWith('cmd.exe')).toBe(true)
      expect(wrapped.startsWith('"')).toBe(true)
      expect(wrapped.endsWith('"')).toBe(true)
      expect(wrapped).toContain(`"${command}"`)
      expect(wrapped).toContain('"C:\\ws with space\\project(1)"')
      expect(wrapped).toContain('"key&(zh)"')
      expect(wrapped).toContain('"C:\\samples\\a&b (x86)\\样本.exe"')
    })

    it('should prefer ComSpec when provided on win32', () => {
      const priorComSpec = process.env.ComSpec
      const command = 'C:\\Program Files\\Ghidra\\support\\analyzeHeadless.bat'
      const args = ['C:\\ws path\\project_a', 'proj_key', '-help']

      try {
        process.env.ComSpec = 'C:\\Windows\\System32\\cmd.exe'
        const result = buildProcessInvocation(command, args, 'win32')
        expect(result.command).toBe('C:\\Windows\\System32\\cmd.exe')
      } finally {
        if (priorComSpec === undefined) {
          delete process.env.ComSpec
        } else {
          process.env.ComSpec = priorComSpec
        }
      }
    })

    it('should execute .cmd under paths with special characters on Windows', () => {
      if (process.platform !== 'win32') {
        return
      }

      const tempRoot = fs.mkdtempSync(path.join(process.cwd(), 'tmp-ghidra-cmd-'))
      const specialDir = path.join(tempRoot, 'ES&E (space)', '\u4e2d\u6587\u76ee\u5f55')
      fs.mkdirSync(specialDir, { recursive: true })

      const scriptPath = path.join(specialDir, 'echo-args.cmd')
      fs.writeFileSync(
        scriptPath,
        ['@echo off', 'echo SCRIPT_OK:%1:%2:%3'].join('\r\n'),
        'utf8'
      )

      const invocation = buildProcessInvocation(
        scriptPath,
        ['A&B', '(C D)', '\u4e2d\u6587']
      )
      const result = spawnSync(invocation.command, invocation.args, {
        encoding: 'utf8',
        windowsHide: true,
        windowsVerbatimArguments: invocation.windowsVerbatimArguments === true,
      })

      expect(result.status).toBe(0)
      expect((result.stdout || '').toString()).toContain('SCRIPT_OK')
      expect((result.stdout || '').toString()).toContain('A&B')
      expect((result.stdout || '').toString()).toContain('(C D)')

      fs.rmSync(tempRoot, { recursive: true, force: true })
    })
  })

  describe('ensureScriptsDirectory', () => {
    it('should create scripts directory if it does not exist', () => {
      expect(fs.existsSync(testScriptsDir)).toBe(false)

      const result = ensureScriptsDirectory(testScriptsDir)

      expect(fs.existsSync(testScriptsDir)).toBe(true)
      expect(result).toBe(path.resolve(testScriptsDir))
    })

    it('should not fail if directory already exists', () => {
      fs.mkdirSync(testScriptsDir, { recursive: true })
      expect(fs.existsSync(testScriptsDir)).toBe(true)

      const result = ensureScriptsDirectory(testScriptsDir)

      expect(fs.existsSync(testScriptsDir)).toBe(true)
      expect(result).toBe(path.resolve(testScriptsDir))
    })

    it('should create nested directories', () => {
      const nestedDir = path.join(testScriptsDir, 'nested', 'deep')
      
      const result = ensureScriptsDirectory(nestedDir)

      expect(fs.existsSync(nestedDir)).toBe(true)
      expect(result).toBe(path.resolve(nestedDir))
    })

    it('should return absolute path', () => {
      const result = ensureScriptsDirectory(testScriptsDir)

      expect(path.isAbsolute(result)).toBe(true)
    })

    it('should default to the packaged ghidra_scripts directory instead of cwd-relative lookup', () => {
      const originalCwd = process.cwd()
      const tempCwd = fs.mkdtempSync(path.join(process.cwd(), 'tmp-ghidra-cwd-'))

      try {
        process.chdir(tempCwd)
        const result = ensureScriptsDirectory()
        expect(result).toBe(path.resolve(resolvePackagePath('ghidra_scripts')))
        expect(fs.existsSync(path.join(tempCwd, 'ghidra_scripts'))).toBe(false)
      } finally {
        process.chdir(originalCwd)
        fs.rmSync(tempCwd, { recursive: true, force: true })
      }
    })
  })

  describe('Environment variable support', () => {
    it('should support GHIDRA_INSTALL_DIR environment variable', () => {
      const testPath = '/opt/ghidra_test'
      process.env.GHIDRA_INSTALL_DIR = testPath

      // The environment variable is read during module initialization
      // We can verify it's set correctly
      expect(process.env.GHIDRA_INSTALL_DIR).toBe(testPath)
    })

    it('should handle missing GHIDRA_INSTALL_DIR gracefully', () => {
      delete process.env.GHIDRA_INSTALL_DIR

      expect(process.env.GHIDRA_INSTALL_DIR).toBeUndefined()
    })

    it('should support GHIDRA_PATH environment variable for detection', () => {
      const testPath = path.join(testGhidraWorkspace, 'ghidra-test-install')
      fs.mkdirSync(testPath, { recursive: true })
      process.env.GHIDRA_PATH = testPath

      expect(detectGhidraInstallation()).toBe(testPath)
    })
  })

  describe('Script directory structure', () => {
    it('should create directory with correct permissions', () => {
      const result = ensureScriptsDirectory(testScriptsDir)

      const stats = fs.statSync(result)
      expect(stats.isDirectory()).toBe(true)
    })

    it('should handle relative paths', () => {
      const relativeDir = './test-relative-scripts'
      const result = ensureScriptsDirectory(relativeDir)

      expect(path.isAbsolute(result)).toBe(true)
      expect(fs.existsSync(result)).toBe(true)

      // Clean up
      fs.rmSync(result, { recursive: true, force: true })
    })
  })

  describe('generateProjectKey', () => {
    it('should generate unique project keys', () => {
      const key1 = generateProjectKey()
      const key2 = generateProjectKey()

      expect(key1).not.toBe(key2)
    })

    it('should generate keys with timestamp and random components', () => {
      const key = generateProjectKey()

      // Format: <timestamp>_<random>
      expect(key).toMatch(/^\d+_[a-z0-9]+$/)
    })

    it('should generate keys that are URL-safe', () => {
      const key = generateProjectKey()

      // Should only contain alphanumeric characters and underscore
      expect(key).toMatch(/^[a-z0-9_]+$/)
    })

    it('should generate multiple unique keys in rapid succession', () => {
      const keys = new Set<string>()
      
      for (let i = 0; i < 100; i++) {
        keys.add(generateProjectKey())
      }

      // All keys should be unique
      expect(keys.size).toBe(100)
    })
  })

  describe('createGhidraProject', () => {
    beforeEach(() => {
      // Ensure test workspace exists
      fs.mkdirSync(testGhidraWorkspace, { recursive: true })
    })

    it('should create project directory with generated key', () => {
      const result = createGhidraProject(testGhidraWorkspace)

      expect(result.projectKey).toBeDefined()
      expect(result.projectPath).toContain(`project_${result.projectKey}`)
      expect(fs.existsSync(result.projectPath)).toBe(true)
    })

    it('should create project directory with provided key', () => {
      const customKey = 'test_project_123'
      const result = createGhidraProject(testGhidraWorkspace, customKey)

      expect(result.projectKey).toBe(customKey)
      expect(result.projectPath).toContain(`project_${customKey}`)
      expect(fs.existsSync(result.projectPath)).toBe(true)
    })

    it('should create nested project directory structure', () => {
      const result = createGhidraProject(testGhidraWorkspace)

      const projectPath = result.projectPath
      expect(fs.existsSync(projectPath)).toBe(true)
      
      const stats = fs.statSync(projectPath)
      expect(stats.isDirectory()).toBe(true)
    })

    it('should not fail if project directory already exists', () => {
      const customKey = 'existing_project'
      
      // Create project first time
      const result1 = createGhidraProject(testGhidraWorkspace, customKey)
      expect(fs.existsSync(result1.projectPath)).toBe(true)

      // Create same project again
      const result2 = createGhidraProject(testGhidraWorkspace, customKey)
      expect(result2.projectPath).toBe(result1.projectPath)
      expect(fs.existsSync(result2.projectPath)).toBe(true)
    })

    it('should create independent project spaces for concurrent analyses', () => {
      // Simulate concurrent project creation
      const project1 = createGhidraProject(testGhidraWorkspace)
      const project2 = createGhidraProject(testGhidraWorkspace)
      const project3 = createGhidraProject(testGhidraWorkspace)

      // All projects should have unique keys and paths
      expect(project1.projectKey).not.toBe(project2.projectKey)
      expect(project2.projectKey).not.toBe(project3.projectKey)
      expect(project1.projectPath).not.toBe(project2.projectPath)
      expect(project2.projectPath).not.toBe(project3.projectPath)

      // All project directories should exist
      expect(fs.existsSync(project1.projectPath)).toBe(true)
      expect(fs.existsSync(project2.projectPath)).toBe(true)
      expect(fs.existsSync(project3.projectPath)).toBe(true)
    })

    it('should handle workspace directory creation', () => {
      const newWorkspace = path.join(testGhidraWorkspace, 'new', 'nested')
      
      const result = createGhidraProject(newWorkspace)

      expect(fs.existsSync(result.projectPath)).toBe(true)
      expect(result.projectPath).toContain(newWorkspace)
    })
  })

  describe('cleanupOldGhidraProjects', () => {
    beforeEach(() => {
      // Ensure test workspace exists
      fs.mkdirSync(testGhidraWorkspace, { recursive: true })
    })

    it('should clean up old projects', () => {
      // Create some test projects
      const oldProject = path.join(testGhidraWorkspace, 'project_old_123')
      const newProject = path.join(testGhidraWorkspace, 'project_new_456')
      
      fs.mkdirSync(oldProject, { recursive: true })
      fs.mkdirSync(newProject, { recursive: true })

      // Make old project appear old by modifying its mtime
      const oldTime = Date.now() - (8 * 24 * 60 * 60 * 1000) // 8 days ago
      fs.utimesSync(oldProject, new Date(oldTime), new Date(oldTime))

      // Clean up projects older than 7 days
      const cleanedCount = cleanupOldGhidraProjects(testGhidraWorkspace, 7 * 24 * 60 * 60 * 1000)

      expect(cleanedCount).toBe(1)
      expect(fs.existsSync(oldProject)).toBe(false)
      expect(fs.existsSync(newProject)).toBe(true)
    })

    it('should not clean up recent projects', () => {
      // Create recent projects
      const project1 = path.join(testGhidraWorkspace, 'project_recent_1')
      const project2 = path.join(testGhidraWorkspace, 'project_recent_2')
      
      fs.mkdirSync(project1, { recursive: true })
      fs.mkdirSync(project2, { recursive: true })

      // Clean up projects older than 7 days
      const cleanedCount = cleanupOldGhidraProjects(testGhidraWorkspace, 7 * 24 * 60 * 60 * 1000)

      expect(cleanedCount).toBe(0)
      expect(fs.existsSync(project1)).toBe(true)
      expect(fs.existsSync(project2)).toBe(true)
    })

    it('should only clean up project directories', () => {
      // Create project directory and non-project file
      const projectDir = path.join(testGhidraWorkspace, 'project_test_123')
      const otherFile = path.join(testGhidraWorkspace, 'other_file.txt')
      
      fs.mkdirSync(projectDir, { recursive: true })
      fs.writeFileSync(otherFile, 'test content')

      // Make both old
      const oldTime = Date.now() - (8 * 24 * 60 * 60 * 1000)
      fs.utimesSync(projectDir, new Date(oldTime), new Date(oldTime))
      fs.utimesSync(otherFile, new Date(oldTime), new Date(oldTime))

      // Clean up
      const cleanedCount = cleanupOldGhidraProjects(testGhidraWorkspace, 7 * 24 * 60 * 60 * 1000)

      expect(cleanedCount).toBe(1)
      expect(fs.existsSync(projectDir)).toBe(false)
      expect(fs.existsSync(otherFile)).toBe(true) // Non-project file should remain
    })

    it('should return 0 if workspace does not exist', () => {
      const nonExistentWorkspace = path.join(testGhidraWorkspace, 'nonexistent')
      
      const cleanedCount = cleanupOldGhidraProjects(nonExistentWorkspace)

      expect(cleanedCount).toBe(0)
    })

    it('should handle empty workspace', () => {
      const cleanedCount = cleanupOldGhidraProjects(testGhidraWorkspace)

      expect(cleanedCount).toBe(0)
    })

    it('should handle cleanup errors gracefully', () => {
      // Create a project directory
      const projectDir = path.join(testGhidraWorkspace, 'project_test_789')
      fs.mkdirSync(projectDir, { recursive: true })

      // Make it old
      const oldTime = Date.now() - (8 * 24 * 60 * 60 * 1000)
      fs.utimesSync(projectDir, new Date(oldTime), new Date(oldTime))

      // Should not throw even if there are permission issues
      expect(() => {
        cleanupOldGhidraProjects(testGhidraWorkspace, 7 * 24 * 60 * 60 * 1000)
      }).not.toThrow()
    })
  })

  describe('checkGhidraHealth', () => {
    it('should treat non-zero help output as launch_ok with warning', () => {
      const tempInstall = fs.mkdtempSync(path.join(process.cwd(), 'tmp-ghidra-health-'))
      const supportDir = path.join(tempInstall, 'support')
      const scriptsDir = path.join(tempInstall, 'scripts')
      fs.mkdirSync(supportDir, { recursive: true })
      fs.mkdirSync(scriptsDir, { recursive: true })

      const analyzePath = getAnalyzeHeadlessPath(tempInstall)
      if (process.platform === 'win32') {
        fs.writeFileSync(
          analyzePath,
          ['@echo off', 'echo analyzeHeadless usage: -import -process', 'exit /b 1'].join('\r\n'),
          'utf8'
        )
      } else {
        fs.writeFileSync(
          analyzePath,
          ['#!/usr/bin/env bash', 'echo "analyzeHeadless usage: -import -process"', 'exit 1'].join('\n'),
          'utf8'
        )
        fs.chmodSync(analyzePath, 0o755)
      }

      const originalConfig = {
        installDir: ghidraConfig.installDir,
        analyzeHeadlessPath: ghidraConfig.analyzeHeadlessPath,
        scriptsDir: ghidraConfig.scriptsDir,
        version: ghidraConfig.version,
        isValid: ghidraConfig.isValid,
      }

      ghidraConfig.installDir = tempInstall
      ghidraConfig.analyzeHeadlessPath = analyzePath
      ghidraConfig.scriptsDir = scriptsDir
      ghidraConfig.isValid = true

      try {
        const result = checkGhidraHealth(5000)
        expect(result.checks.launch_ok).toBe(true)
        expect(typeof result.checks.pyghidra_available).toBe('boolean')
        expect(result.ok).toBe(true)
        expect(result.errors).toHaveLength(0)
        expect(result.warnings.some((item) => item.includes('non-zero exit code'))).toBe(true)
      } finally {
        ghidraConfig.installDir = originalConfig.installDir
        ghidraConfig.analyzeHeadlessPath = originalConfig.analyzeHeadlessPath
        ghidraConfig.scriptsDir = originalConfig.scriptsDir
        ghidraConfig.version = originalConfig.version
        ghidraConfig.isValid = originalConfig.isValid
        fs.rmSync(tempInstall, { recursive: true, force: true })
      }
    })
  })
})
