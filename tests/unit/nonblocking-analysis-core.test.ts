/**
 * Unit tests for nonblocking analysis pipeline - core logic
 * Tasks: 5.1 - run reuse logic, compatibility markers, stage state machine
 */

import { describe, test, expect } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  buildAnalysisRunCompatibilityMarker,
  buildStagePlan,
  ANALYSIS_PIPELINE_VERSION,
  createOrReuseAnalysisRun,
} from '../../src/analysis-run-state.js'
import type { AnalysisPipelineStage } from '../../src/analysis-run-state.js'
import { DatabaseManager } from '../../src/database.js'

describe('nonblocking analysis pipeline - core logic', () => {
  describe('buildAnalysisRunCompatibilityMarker', () => {
    test('should build deterministic compatibility marker', () => {
      const marker1 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'triage',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      const marker2 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'triage',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      // Should be deterministic (same inputs produce same marker)
      expect(marker1).toBe(marker2)
      expect(marker1).toHaveLength(64) // SHA256 hex length
    })

    test('should produce different markers for different goals', () => {
      const marker1 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'triage',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      const marker2 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'reverse',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      expect(marker1).not.toBe(marker2)
    })

    test('should produce different markers for different depths', () => {
      const marker1 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'triage',
        depth: 'balanced',
        backendPolicy: 'auto',
      })

      const marker2 = buildAnalysisRunCompatibilityMarker({
        sampleSha256: 'abc123',
        goal: 'triage',
        depth: 'deep',
        backendPolicy: 'auto',
      })

      expect(marker1).not.toBe(marker2)
    })
  })

  describe('buildStagePlan', () => {
    test('should build stage plan for triage goal', () => {
      const plan = buildStagePlan('triage')
      expect(plan).toContain('fast_profile')
      expect(plan).toContain('summarize')
    })

    test('should build stage plan for reverse goal', () => {
      const plan = buildStagePlan('reverse')
      expect(plan).toContain('fast_profile')
      expect(plan).toContain('function_map')
      expect(plan).toContain('reconstruct')
    })

    test('should build stage plan for dynamic goal', () => {
      const plan = buildStagePlan('dynamic')
      expect(plan).toContain('fast_profile')
      expect(plan).toContain('dynamic_plan')
      expect(plan).toContain('dynamic_execute')
    })

    test('should include fast_profile and summarize in all plans', () => {
      const goals: Array<'triage' | 'static' | 'reverse' | 'dynamic' | 'report'> = [
        'triage',
        'static',
        'reverse',
        'dynamic',
        'report',
      ]

      for (const goal of goals) {
        const plan = buildStagePlan(goal)
        expect(plan).toContain('fast_profile')
        expect(plan).toContain('summarize')
      }
    })
  })

  describe('pipeline version constant', () => {
    test('should have valid pipeline version', () => {
      expect(ANALYSIS_PIPELINE_VERSION).toBeDefined()
      expect(ANALYSIS_PIPELINE_VERSION).toContain('nonblocking')
      expect(ANALYSIS_PIPELINE_VERSION).toContain('v')
    })
  })

  describe('createOrReuseAnalysisRun', () => {
    test('should reuse a compatible persisted run for the same sample and intent', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-run-reuse-'))
      const dbPath = path.join(tempDir, 'test.db')
      const database = new DatabaseManager(dbPath)

      try {
        const sample = {
          id: 'sha256:' + 'a'.repeat(64),
          sha256: 'a'.repeat(64),
          md5: 'a'.repeat(32),
          size: 2048,
          file_type: 'PE32+',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        }
        database.insertSample(sample)

        const first = createOrReuseAnalysisRun(database, {
          sample,
          goal: 'triage',
          depth: 'balanced',
          backendPolicy: 'auto',
        })
        const second = createOrReuseAnalysisRun(database, {
          sample,
          goal: 'triage',
          depth: 'balanced',
          backendPolicy: 'auto',
        })

        expect(first.reused).toBe(false)
        expect(second.reused).toBe(true)
        expect(second.run.id).toBe(first.run.id)
        expect(second.compatibilityMarker).toBe(first.compatibilityMarker)
        expect(second.stagePlan).toEqual(first.stagePlan)
      } finally {
        database.close()
        fs.rmSync(tempDir, { recursive: true, force: true })
      }
    })
  })
})
