import { describe, expect, test } from '@jest/globals'
import { buildIntentBackendPlan } from '../../src/intent-routing.js'
import type { ToolchainBackendResolution } from '../../src/static-backend-discovery.js'

function createReadyBackends(): ToolchainBackendResolution {
  return {
    capa_cli: { available: true, source: 'path', path: '/tool/capa', version: '1', checked_candidates: ['capa'], error: null },
    capa_rules: { available: true, source: 'env', path: '/rules/capa', error: null },
    die: { available: true, source: 'path', path: '/tool/diec', version: '1', checked_candidates: ['diec'], error: null },
    graphviz: { available: true, source: 'path', path: '/tool/dot', version: '1', checked_candidates: ['dot'], error: null },
    rizin: { available: true, source: 'path', path: '/tool/rizin', version: '1', checked_candidates: ['rizin'], error: null },
    upx: { available: true, source: 'path', path: '/tool/upx', version: '1', checked_candidates: ['upx'], error: null },
    wine: { available: true, source: 'path', path: '/tool/wine', version: '1', checked_candidates: ['wine'], error: null },
    winedbg: { available: true, source: 'path', path: '/tool/winedbg', version: '1', checked_candidates: ['winedbg'], error: null },
    frida_cli: { available: true, source: 'path', path: '/tool/frida-ps', version: '1', checked_candidates: ['frida-ps'], error: null },
    yara_x: { available: true, source: 'path', path: '/tool/python3', version: '1', checked_candidates: ['python3'], error: null },
    qiling: { available: true, source: 'path', path: '/tool/qiling-python', version: '1', checked_candidates: ['python3'], error: null },
    angr: { available: true, source: 'path', path: '/tool/angr-python', version: '1', checked_candidates: ['python3'], error: null },
    panda: { available: true, source: 'path', path: '/tool/panda-python', version: '1', checked_candidates: ['python3'], error: null },
    retdec: { available: true, source: 'path', path: '/tool/retdec-decompiler', version: '1', checked_candidates: ['retdec-decompiler'], error: null },
  }
}

describe('intent routing', () => {
  test('should select safe triage corroboration backends when evidence is weak', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'triage',
      depth: 'deep',
      backendPolicy: 'prefer_new',
      readiness: createReadyBackends(),
      signals: {
        packer_suspected: true,
        legacy_yara_weak: true,
        degraded_structure: true,
        yara_x_rules_ready: true,
      },
    })

    expect(metadata.backend_selected.map((item) => item.tool)).toEqual(
      expect.arrayContaining(['upx.inspect', 'yara_x.scan', 'rizin.analyze'])
    )
    expect(metadata.backend_escalation_reasons.length).toBeGreaterThanOrEqual(3)
  })

  test('should suppress corroborating backends when backend_policy=legacy_only', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'reverse',
      depth: 'deep',
      backendPolicy: 'legacy_only',
      readiness: createReadyBackends(),
      signals: {
        weak_function_coverage: true,
        degraded_reconstruction: true,
      },
    })

    expect(metadata.backend_selected).toHaveLength(0)
    expect(metadata.backend_skipped.some((item) => item.reason.includes('legacy_only'))).toBe(true)
  })

  test('should keep wine as manual-only for dynamic routing', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'dynamic',
      depth: 'balanced',
      backendPolicy: 'auto',
      readiness: createReadyBackends(),
      signals: {
        qiling_rootfs_ready: true,
      },
    })

    expect(metadata.manual_only_backends.map((item) => item.tool)).toContain('wine.run')
    expect(metadata.backend_selected.map((item) => item.tool)).toContain('qiling.inspect')
  })

  test('should expose explicit stage backend roles and omission reasons', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'reverse',
      depth: 'balanced',
      backendPolicy: 'auto',
      readiness: createReadyBackends(),
      signals: {
        weak_function_coverage: true,
        degraded_reconstruction: true,
      },
    })

    expect(
      metadata.stage_backend_roles.some(
        (item) =>
          item.stage === 'fast_profile' &&
          item.backend === 'rizin' &&
          item.execution_bucket === 'preview-static' &&
          item.cost_class === 'cheap' &&
          item.worker_family === 'rizin.preview'
      )
    ).toBe(true)
    expect(
      metadata.stage_backend_roles.some(
        (item) =>
          item.stage === 'reconstruct' &&
          item.backend === 'retdec' &&
          item.selection_policy === 'fallback'
      )
    ).toBe(true)
    expect(metadata.omitted_backend_reasons.length).toBeGreaterThanOrEqual(1)
  })

  test('should prefer rizin during large-sample preview routing even without degraded PE signals', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'triage',
      depth: 'balanced',
      backendPolicy: 'auto',
      readiness: createReadyBackends(),
      signals: {
        large_sample_preview: true,
      },
    })

    expect(metadata.backend_selected.map((item) => item.tool)).toContain('rizin.analyze')
  })

  test('should route packed and debug-aware dynamic intent through planning backends before manual execution', () => {
    const metadata = buildIntentBackendPlan({
      goal: 'dynamic',
      depth: 'balanced',
      backendPolicy: 'auto',
      readiness: createReadyBackends(),
      signals: {
        packer_suspected: true,
        packed_confirmed: true,
        debug_requested: true,
      },
    })

    expect(metadata.backend_selected.map((item) => item.tool)).toEqual(
      expect.arrayContaining(['qiling.inspect', 'panda.inspect'])
    )
    expect(
      metadata.stage_backend_roles.some(
        (item) =>
          item.stage === 'dynamic_plan' &&
          item.tool === 'upx.inspect' &&
          item.role === 'safe_unpack_probe'
      )
    ).toBe(true)
    expect(metadata.manual_only_backends.map((item) => item.tool)).toEqual(
      expect.arrayContaining(['frida.trace.capture', 'wine.run'])
    )
  })
})
