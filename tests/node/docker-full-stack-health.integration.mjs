import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const { WorkspaceManager } = await import('../../dist/workspace-manager.js')
const { DatabaseManager } = await import('../../dist/database.js')
const { CacheManager } = await import('../../dist/cache-manager.js')
const { createSystemHealthHandler } = await import('../../dist/tools/system-health.js')
const { createDynamicDependenciesHandler } = await import('../../dist/tools/dynamic-dependencies.js')

function buildGhidraStatus(ok) {
  return {
    ok,
    checked_at: new Date().toISOString(),
    install_dir: ok ? '/opt/ghidra' : '',
    analyze_headless_path: ok ? '/opt/ghidra/support/analyzeHeadless' : '',
    scripts_dir: path.join(process.cwd(), 'ghidra_scripts'),
    project_root: path.join(process.cwd(), 'ghidra-projects'),
    log_root: path.join(process.cwd(), 'ghidra-logs'),
    version: ok ? '12.0.4' : undefined,
    checks: {
      install_dir_exists: ok,
      analyze_headless_exists: ok,
      scripts_dir_exists: true,
      launch_ok: ok,
      pyghidra_available: ok,
      java_available: ok,
      java_version_ok: ok,
    },
    pyghidra_probe: {
      command: 'python3',
      available: ok,
      version: ok ? '1.0.0' : undefined,
      error: ok ? undefined : 'pyghidra missing',
    },
    java_probe: {
      command: 'java',
      available: ok,
      source: ok ? 'PATH' : 'none',
      version: ok ? 'openjdk version "21.0.2"' : undefined,
      major_version: ok ? 21 : undefined,
      version_ok: ok,
      error: ok ? undefined : 'java missing',
    },
    errors: ok ? [] : ['install dir not found'],
    warnings: [],
  }
}

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'docker-full-stack-health-'))
const workspaceRoot = path.join(tempRoot, 'workspaces')
const dbPath = path.join(tempRoot, 'test.db')
const cacheRoot = path.join(tempRoot, 'cache')

const workspaceManager = new WorkspaceManager(workspaceRoot)
const database = new DatabaseManager(dbPath)
const cacheManager = new CacheManager(cacheRoot, database)

try {
  const systemHealth = createSystemHealthHandler(workspaceManager, database, {
    checkGhidra: () => buildGhidraStatus(true),
    cacheManager,
    probeStaticWorker: async () => ({
      status: 'healthy',
      worker: { python_version: '3.11.9' },
      dependencies: {
        pefile: { available: true },
        lief: { available: true },
        capa: { available: true },
        frida: { available: true },
      },
    }),
  })

  const healthResult = await systemHealth({})
  assert.equal(healthResult.ok, true)
  assert.equal(healthResult.data.components.static_worker.status, 'healthy')
  assert.ok(healthResult.data.components.static_worker.details.external_backends.graphviz)
  assert.ok(healthResult.data.components.static_worker.details.external_backends.rizin)
  assert.ok(healthResult.data.components.static_worker.details.external_backends.qiling)
  assert.ok(healthResult.data.components.static_worker.details.external_backends.retdec)

  const dynamicDependencies = createDynamicDependenciesHandler(workspaceManager, database, {
    callWorker: async () => ({
      job_id: 'job-1',
      ok: true,
      warnings: [],
      errors: [],
      data: {
        status: 'partial',
        available_components: ['speakeasy'],
        components: {
          speakeasy: { available: true, version: '1.5.11' },
          frida: { available: true, version: '17.8.0' },
          psutil: { available: true, version: '7.2.2' },
        },
        recommendations: [],
        checked_at: new Date().toISOString(),
      },
      artifacts: [],
      metrics: { elapsed_ms: 1, tool: 'dynamic.dependencies' },
    }),
  })

  const dynamicResult = await dynamicDependencies({})
  assert.equal(dynamicResult.ok, true)
  assert.ok(dynamicResult.data.components.qiling)
  assert.ok(dynamicResult.data.components.angr)
  assert.ok(dynamicResult.data.components.panda)
  assert.ok(dynamicResult.data.components.wine)
  assert.ok(dynamicResult.data.components.winedbg)
  assert.ok(dynamicResult.data.components.frida_cli)
  assert.ok(Array.isArray(dynamicResult.data.required_user_inputs))
  assert.ok(dynamicResult.data.recommendations.length >= 0)

  console.log('docker full stack health integration checks passed')
} finally {
  database.close()
  await fs.rm(tempRoot, { recursive: true, force: true })
}
