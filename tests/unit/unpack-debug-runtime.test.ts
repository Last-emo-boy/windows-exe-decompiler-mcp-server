import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE,
  DEBUG_SESSION_ARTIFACT_TYPE,
  UNPACK_PLAN_ARTIFACT_TYPE,
  buildDynamicBehaviorDiffDigest,
  buildPackedVsUnpackedDiffDigest,
  buildUnpackPlan,
  createDebugSessionRecord,
  loadUnpackDebugArtifactSelection,
  parseDatabaseDebugSession,
  persistUnpackDebugJsonArtifact,
  toDatabaseDebugSession,
} from '../../src/unpack-debug-runtime.js'

describe('unpack-debug runtime helpers', () => {
  test('builds a bounded UPX unpack plan for packed samples', () => {
    const sample = {
      id: `sha256:${'a'.repeat(64)}`,
      sha256: 'a'.repeat(64),
    }

    const previewOnly = buildUnpackPlan({
      sample,
      packerDetected: true,
      packerConfidence: 0.88,
      packerNames: ['UPX 4.x'],
      upxValidationPassed: true,
      upxReady: true,
      rizinReady: true,
      allowTransformations: false,
      allowLiveExecution: false,
    })

    expect(previewOnly.packed_state).toBe('confirmed_packed')
    expect(previewOnly.strategy).toBe('upx_decompress')
    expect(previewOnly.safety_level).toBe('preview_only')
    expect(previewOnly.next_safe_step).toBe('preview_only')
    expect(previewOnly.proposed_backends.some((item) => item.tool === 'upx.inspect')).toBe(true)

    const dumpOriented = buildUnpackPlan({
      sample,
      packerDetected: true,
      packerNames: ['UPX'],
      upxValidationPassed: true,
      upxReady: true,
      rizinReady: true,
      allowTransformations: true,
      allowLiveExecution: false,
    })

    expect(dumpOriented.safety_level).toBe('dump_oriented')
    expect(dumpOriented.next_safe_step).toBe('dump_oriented')
    expect(dumpOriented.next_actions.some((item) => item.includes('safe UPX-backed unpack attempt'))).toBe(
      true
    )
  })

  test('round-trips persisted debug sessions', () => {
    const session = createDebugSessionRecord({
      runId: 'run-debug',
      sample: {
        id: `sha256:${'b'.repeat(64)}`,
        sha256: 'b'.repeat(64),
      },
      status: 'planned',
      debugState: 'planned',
      backend: 'frida.trace.capture',
      currentPhase: 'trace_plan',
      sessionTag: 'debug/run-debug',
      artifactRefs: [
        {
          id: 'artifact-1',
          type: DEBUG_SESSION_ARTIFACT_TYPE,
          path: 'reports/debug_session/debug/run-debug/session.json',
          sha256: 'c'.repeat(64),
          mime: 'application/json',
        },
      ],
      guidance: {
        recommended_next_tools: ['trace.condition', 'workflow.analyze.status'],
        next_actions: ['Use trace.condition before live capture.'],
      },
      metadata: {
        source_stage: 'dynamic_plan',
      },
    })

    const parsed = parseDatabaseDebugSession(toDatabaseDebugSession(session))
    expect(parsed).toEqual(session)
  })

  test('persists and reloads unpack artifacts by session selector', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unpack-debug-runtime-'))
    const database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    const sampleId = `sha256:${'d'.repeat(64)}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: 'd'.repeat(64),
        md5: 'd'.repeat(32),
        size: 4096,
        file_type: 'PE32+',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      await workspaceManager.createWorkspace(sampleId)

      const artifact = await persistUnpackDebugJsonArtifact(
        workspaceManager,
        database,
        sampleId,
        UNPACK_PLAN_ARTIFACT_TYPE,
        'unpack_plan',
        {
          plan_id: 'plan-1',
          sample_id: sampleId,
          packed_state: 'confirmed_packed',
          unpack_state: 'unpack_planned',
          unpack_confidence: 0.91,
          safety_level: 'preview_only',
          strategy: 'upx_decompress',
          next_safe_step: 'preview_only',
          evidence: ['UPX markers'],
          proposed_backends: [],
          expected_artifacts: ['unpack_execution_digest'],
          recommended_next_tools: ['workflow.analyze.promote'],
          next_actions: ['Promote into dynamic planning.'],
          session_tag: 'analysis/run-1',
        },
        'analysis/run-1'
      )

      const selection = await loadUnpackDebugArtifactSelection<{ plan_id: string; packed_state: string }>(
        workspaceManager,
        database,
        sampleId,
        UNPACK_PLAN_ARTIFACT_TYPE,
        {
          scope: 'session',
          sessionTag: 'analysis/run-1',
        }
      )

      expect(selection.latest_artifact?.id).toBe(artifact.id)
      expect(selection.latest_payload?.plan_id).toBe('plan-1')
      expect(selection.latest_payload?.packed_state).toBe('confirmed_packed')
      expect(selection.scope_note).toContain('scope=session')
      expect(selection.session_tags).toContain('analysis/run-1')
    } finally {
      database.close()
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  test('builds bounded packed and dynamic diff digests', () => {
    const packedDiff = buildPackedVsUnpackedDiffDigest({
      sampleId: `sha256:${'e'.repeat(64)}`,
      sizeBefore: 1024,
      sizeAfter: 4096,
      importsBefore: ['kernel32!LoadLibraryA'],
      importsAfter: ['kernel32!LoadLibraryA', 'advapi32!RegSetValueExW'],
      stringsBefore: ['stub'],
      stringsAfter: ['stub', 'http://example.invalid'],
      sectionCountBefore: 3,
      sectionCountAfter: 6,
      sourceArtifactRefs: [],
    })

    expect(packedDiff.diff_type).toBe(ANALYSIS_DIFF_DIGEST_ARTIFACT_TYPE === 'analysis_diff_digest' ? 'packed_vs_unpacked' : 'packed_vs_unpacked')
    expect(packedDiff.findings.some((item) => item.includes('Section count changed'))).toBe(true)
    expect(packedDiff.findings.some((item) => item.includes('New imports became visible'))).toBe(true)

    const dynamicDiff = buildDynamicBehaviorDiffDigest({
      sampleId: `sha256:${'f'.repeat(64)}`,
      diffType: 'pre_vs_post_dynamic',
      beforeSummary: {
        observed_apis: ['CreateFileW'],
        stages: ['safe_simulation'],
        risk_hints: ['filesystem'],
      },
      afterSummary: {
        observed_apis: ['CreateFileW', 'WinHttpSendRequest'],
        stages: ['safe_simulation', 'trace_capture'],
        risk_hints: ['filesystem', 'network'],
        summary: 'Network activity became visible after trace capture.',
      },
      sourceArtifactRefs: [],
    })

    expect(dynamicDiff.diff_type).toBe('pre_vs_post_dynamic')
    expect(dynamicDiff.findings.some((item) => item.includes('New runtime-observed APIs'))).toBe(true)
    expect(dynamicDiff.findings.some((item) => item.includes('New runtime stages'))).toBe(true)
  })
})
