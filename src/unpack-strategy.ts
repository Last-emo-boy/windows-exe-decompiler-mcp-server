/**
 * Unpack strategy routing table
 * Maps packer detection results to unpack backends with confidence thresholds
 */

import { z } from 'zod'
import { execFile } from 'child_process'
import { promisify } from 'util'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { createHash, randomUUID } from 'crypto'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import {
  resolveAnalysisBackends,
} from './static-backend-discovery.js'

const execFileAsync = promisify(execFile)

// ============================================================================
// Types & Schemas
// ============================================================================

export const UnpackBackendSchema = z.enum([
  'upx_cli',
  'speakeasy_dump',
  'qiling_oep_dump',
])
export type UnpackBackend = z.infer<typeof UnpackBackendSchema>

export interface UnpackStrategyEntry {
  packer_pattern: RegExp
  min_confidence: number
  backend: UnpackBackend
  description: string
}

export interface SelectedStrategy {
  backend: UnpackBackend
  packer_name: string
  confidence: number
  description: string
}

export interface UnpackResult {
  ok: boolean
  unpacked_path: string | null
  backend: UnpackBackend
  error?: string
  exit_code?: number
  stdout_preview?: string
  stderr_preview?: string
}

// ============================================================================
// Strategy Routing Table
// ============================================================================

const STRATEGY_TABLE: UnpackStrategyEntry[] = [
  {
    packer_pattern: /\bupx\b/i,
    min_confidence: 0.3,
    backend: 'upx_cli',
    description: 'UPX detected — use native UPX decompression',
  },
  {
    packer_pattern: /\b(themida|vmprotect|enigma|aspack|petite|mpress|fsg|nspack|pecompact)\b/i,
    min_confidence: 0.5,
    backend: 'speakeasy_dump',
    description: 'Known protector detected — use Speakeasy emulation to dump at OEP',
  },
  {
    packer_pattern: /\b(unknown|custom|generic)\b/i,
    min_confidence: 0.6,
    backend: 'speakeasy_dump',
    description: 'Unknown/custom packer — try Speakeasy memory dump',
  },
]

const HIGH_ENTROPY_FALLBACK: SelectedStrategy = {
  backend: 'speakeasy_dump',
  packer_name: 'high_entropy_unknown',
  confidence: 0,
  description: 'High-entropy binary with no named packer — try Speakeasy emulation dump',
}

// ============================================================================
// Strategy Selection
// ============================================================================

export interface PackerDetectionResult {
  packed: boolean
  confidence: number
  packer_names: string[]
  high_entropy?: boolean
}

export function selectUnpackStrategy(
  packerResult: PackerDetectionResult
): SelectedStrategy | null {
  if (!packerResult.packed) {
    return null
  }

  for (const name of packerResult.packer_names) {
    for (const entry of STRATEGY_TABLE) {
      if (
        entry.packer_pattern.test(name) &&
        packerResult.confidence >= entry.min_confidence
      ) {
        return {
          backend: entry.backend,
          packer_name: name,
          confidence: packerResult.confidence,
          description: entry.description,
        }
      }
    }
  }

  // Fallback for packed binaries with no recognized packer name
  if (packerResult.high_entropy || packerResult.confidence >= 0.5) {
    return {
      ...HIGH_ENTROPY_FALLBACK,
      confidence: packerResult.confidence,
    }
  }

  return null
}

// ============================================================================
// Unpack Backends
// ============================================================================

function truncateStr(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '…' : s
}

export async function executeUpxUnpack(samplePath: string): Promise<UnpackResult> {
  const backends = resolveAnalysisBackends()
  if (!backends.upx.available || !backends.upx.path) {
    return {
      ok: false,
      unpacked_path: null,
      backend: 'upx_cli',
      error: 'UPX binary not available',
    }
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'upx-unpack-'))
  const outputPath = path.join(tempDir, path.basename(samplePath))

  try {
    const result = await execFileAsync(backends.upx.path, ['-d', '-o', outputPath, samplePath], {
      encoding: 'utf8',
      timeout: 60_000,
      windowsHide: true,
      maxBuffer: 4 * 1024 * 1024,
    })

    // Validate that the output file exists and has a PE header
    try {
      const header = Buffer.alloc(2)
      const fh = await fs.open(outputPath, 'r')
      await fh.read(header, 0, 2, 0)
      await fh.close()
      if (header[0] !== 0x4d || header[1] !== 0x5a) {
        return {
          ok: false,
          unpacked_path: null,
          backend: 'upx_cli',
          error: 'UPX output does not have a valid PE header (MZ)',
          exit_code: 0,
          stdout_preview: truncateStr(result.stdout || '', 500),
          stderr_preview: truncateStr(result.stderr || '', 500),
        }
      }
    } catch {
      return {
        ok: false,
        unpacked_path: null,
        backend: 'upx_cli',
        error: 'UPX output file not readable after decompression',
      }
    }

    return {
      ok: true,
      unpacked_path: outputPath,
      backend: 'upx_cli',
      exit_code: 0,
      stdout_preview: truncateStr(result.stdout || '', 500),
      stderr_preview: truncateStr(result.stderr || '', 500),
    }
  } catch (error) {
    const err = error as {
      stdout?: string
      stderr?: string
      code?: number
      signal?: string
    }
    // Clean up temp dir on failure
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
    return {
      ok: false,
      unpacked_path: null,
      backend: 'upx_cli',
      error: `UPX decompress failed: ${err.stderr || err.signal || 'unknown error'}`,
      exit_code: typeof err.code === 'number' ? err.code : 1,
      stdout_preview: truncateStr(String(err.stdout || ''), 500),
      stderr_preview: truncateStr(String(err.stderr || ''), 500),
    }
  }
}

export async function executeSpeakeasyDump(samplePath: string): Promise<UnpackResult> {
  // Speakeasy is a Python module, not tracked in ToolchainBackendResolution.
  // We attempt to invoke it directly via Python.

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'speakeasy-dump-'))
  const dumpPath = path.join(tempDir, 'memory_dump.bin')
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3'

  const script = `
import sys, json, os
try:
    import speakeasy
    se = speakeasy.Speakeasy()
    se.load_module(sys.argv[1])
    se.run_module(timeout=30)
    dumps = se.get_memory_dumps()
    if dumps:
        largest = max(dumps, key=lambda d: len(d.get('data', b'')))
        with open(sys.argv[2], 'wb') as f:
            f.write(largest['data'])
        print(json.dumps({"ok": True, "dump_size": len(largest['data']), "oep": largest.get('base', None)}))
    else:
        print(json.dumps({"ok": False, "error": "No memory dumps captured"}))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e)}))
`

  try {
    const result = await execFileAsync(
      pythonCmd,
      ['-c', script, samplePath, dumpPath],
      {
        encoding: 'utf8',
        timeout: 120_000,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024,
      }
    )

    try {
      const output = JSON.parse(result.stdout.trim())
      if (output.ok) {
        return {
          ok: true,
          unpacked_path: dumpPath,
          backend: 'speakeasy_dump',
          exit_code: 0,
          stdout_preview: truncateStr(result.stdout, 500),
        }
      }
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
      return {
        ok: false,
        unpacked_path: null,
        backend: 'speakeasy_dump',
        error: output.error || 'Speakeasy dump produced no output',
      }
    } catch {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
      return {
        ok: false,
        unpacked_path: null,
        backend: 'speakeasy_dump',
        error: 'Failed to parse Speakeasy output',
        stdout_preview: truncateStr(result.stdout || '', 500),
      }
    }
  } catch (error) {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
    const err = error as { stderr?: string; signal?: string }
    return {
      ok: false,
      unpacked_path: null,
      backend: 'speakeasy_dump',
      error: `Speakeasy execution failed: ${err.stderr || err.signal || 'unknown error'}`,
    }
  }
}

export async function executeQilingDump(samplePath: string): Promise<UnpackResult> {
  const backends = resolveAnalysisBackends()
  if (!backends.qiling.available) {
    return {
      ok: false,
      unpacked_path: null,
      backend: 'qiling_oep_dump',
      error: 'Qiling backend not available',
    }
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qiling-dump-'))
  const dumpPath = path.join(tempDir, 'oep_dump.bin')
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3'

  const script = `
import sys, json, os
try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    rootfs = os.environ.get('QILING_ROOTFS', '/opt/qiling/rootfs/x86_windows')
    ql = Qiling([sys.argv[1]], rootfs, verbose=QL_VERBOSE.DISABLED)
    oep = None
    def oep_hook(ql):
        global oep
        oep = ql.arch.regs.arch_pc
        # Dump from image base
        pe_base = ql.loader.pe_image_address
        pe_size = ql.loader.pe_image_size
        dump = ql.mem.read(pe_base, pe_size)
        with open(sys.argv[2], 'wb') as f:
            f.write(bytes(dump))
        ql.emu_stop()
    # Hook at entry point after unpacking stub runs
    ql.hook_code(oep_hook)
    ql.run(timeout=30)
    if os.path.exists(sys.argv[2]) and os.path.getsize(sys.argv[2]) > 0:
        print(json.dumps({"ok": True, "dump_size": os.path.getsize(sys.argv[2]), "oep": hex(oep) if oep else None}))
    else:
        print(json.dumps({"ok": False, "error": "No OEP dump produced"}))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e)}))
`

  try {
    const result = await execFileAsync(
      pythonCmd,
      ['-c', script, samplePath, dumpPath],
      {
        encoding: 'utf8',
        timeout: 120_000,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024,
      }
    )

    try {
      const output = JSON.parse(result.stdout.trim())
      if (output.ok) {
        return {
          ok: true,
          unpacked_path: dumpPath,
          backend: 'qiling_oep_dump',
          exit_code: 0,
          stdout_preview: truncateStr(result.stdout, 500),
        }
      }
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
      return {
        ok: false,
        unpacked_path: null,
        backend: 'qiling_oep_dump',
        error: output.error || 'Qiling OEP dump produced no output',
      }
    } catch {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
      return {
        ok: false,
        unpacked_path: null,
        backend: 'qiling_oep_dump',
        error: 'Failed to parse Qiling output',
        stdout_preview: truncateStr(result.stdout || '', 500),
      }
    }
  } catch (error) {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
    const err = error as { stderr?: string; signal?: string }
    return {
      ok: false,
      unpacked_path: null,
      backend: 'qiling_oep_dump',
      error: `Qiling execution failed: ${err.stderr || err.signal || 'unknown error'}`,
    }
  }
}

// ============================================================================
// Backend Dispatch
// ============================================================================

export async function executeUnpackBackend(
  backend: UnpackBackend,
  samplePath: string
): Promise<UnpackResult> {
  switch (backend) {
    case 'upx_cli':
      return executeUpxUnpack(samplePath)
    case 'speakeasy_dump':
      return executeSpeakeasyDump(samplePath)
    case 'qiling_oep_dump':
      return executeQilingDump(samplePath)
  }
}

// ============================================================================
// Child Sample Registration
// ============================================================================

export async function registerChildSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  parentId: string,
  unpackedPath: string,
  provenance: {
    backend: UnpackBackend
    packer_name: string
    layer: number
  }
): Promise<{ sample_id: string; sha256: string }> {
  const data = await fs.readFile(unpackedPath)
  const sha256 = createHash('sha256').update(data).digest('hex')
  const md5 = createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  // Check if this sample already exists
  const existing = database.findSample(sampleId)
  if (existing) {
    return { sample_id: sampleId, sha256 }
  }

  // Create workspace and copy binary
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const destPath = path.join(workspace.original, `unpacked_layer_${provenance.layer}.bin`)
  await fs.copyFile(unpackedPath, destPath)

  // Register in database
  const now = new Date().toISOString()
  database.insertSample({
    id: sampleId,
    sha256,
    md5,
    size: data.length,
    file_type: null,
    source: `auto_unpack:${provenance.backend}:parent=${parentId}:layer=${provenance.layer}`,
    created_at: now,
  })

  return { sample_id: sampleId, sha256 }
}
