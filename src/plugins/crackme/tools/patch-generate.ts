/**
 * patch.generate MCP tool — generate binary patches for CrackMe/protection bypass.
 * Supports NOP-out, JMP-always, invert-branch, and custom byte patches.
 * Outputs IPS patch file and/or directly patched binary as a child sample.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import path from 'path'
import crypto from 'crypto'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'patch.generate'

// x86/x64 NOP sled
const NOP = 0x90
// JMP SHORT relative (EB xx)
const JMP_SHORT = 0xEB
// Near JMP relative (E9 xx xx xx xx)
const JMP_NEAR = 0xE9

// x86 conditional jump opcodes (short)
const COND_JUMPS_SHORT = new Set([
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
])

// x86 Jcc near prefixed by 0F
const COND_JUMPS_NEAR_PREFIX = 0x0F
const COND_JUMPS_NEAR_RANGE = [0x80, 0x8F]

export const PatchGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  patches: z.array(z.object({
    address: z.string().describe('Virtual address or file offset (hex, e.g. "0x401234")'),
    type: z.enum(['nop', 'jmp_always', 'invert_branch', 'custom']).describe('Patch type'),
    size: z.number().int().min(1).max(32).optional().describe('Number of bytes to NOP (for nop type)'),
    bytes: z.string().optional().describe('Custom hex bytes (for custom type, e.g. "EB05")'),
    comment: z.string().optional().describe('Human-readable annotation'),
  })).min(1).describe('List of patches to apply'),
  output_format: z.enum(['ips', 'patched_binary', 'both']).optional().default('both'),
  image_base: z.string().optional().describe('Image base address for VA→offset conversion (hex). Auto-detected from PE if omitted.'),
})

export const patchGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate binary patches (NOP, JMP-always, invert-branch, custom bytes) for CrackMe bypass. ' +
    'Outputs IPS patch file and/or patched binary registered as a child sample.',
  inputSchema: PatchGenerateInputSchema,
}

function parseHexAddr(s: string): number {
  return parseInt(s.replace(/^0x/i, ''), 16)
}

function vaToFileOffset(va: number, imageBase: number, sections: Array<{ va: number; rawOffset: number; rawSize: number; virtualSize: number }>): number {
  const rva = va - imageBase
  for (const sec of sections) {
    if (rva >= sec.va && rva < sec.va + Math.max(sec.virtualSize, sec.rawSize)) {
      return sec.rawOffset + (rva - sec.va)
    }
  }
  // Fallback: treat as file offset
  return va
}

function parsePESections(data: Buffer): { imageBase: number; sections: Array<{ va: number; rawOffset: number; rawSize: number; virtualSize: number }> } {
  const peOffset = data.readUInt32LE(0x3C)
  const magic = data.readUInt16LE(peOffset + 24)
  const is64 = magic === 0x20B
  const imageBase = is64 ? Number(data.readBigUInt64LE(peOffset + 24 + 24)) : data.readUInt32LE(peOffset + 24 + 28)
  const numSections = data.readUInt16LE(peOffset + 6)
  const optHeaderSize = data.readUInt16LE(peOffset + 20)
  const sectionStart = peOffset + 24 + optHeaderSize

  const sections: Array<{ va: number; rawOffset: number; rawSize: number; virtualSize: number }> = []
  for (let i = 0; i < numSections; i++) {
    const off = sectionStart + i * 40
    sections.push({
      virtualSize: data.readUInt32LE(off + 8),
      va: data.readUInt32LE(off + 12),
      rawSize: data.readUInt32LE(off + 16),
      rawOffset: data.readUInt32LE(off + 20),
    })
  }
  return { imageBase, sections }
}

function generateIPS(patches: Array<{ offset: number; bytes: Buffer }>): Buffer {
  // IPS format: "PATCH" header, then records [3-byte offset][2-byte size][data], "EOF" trailer
  const chunks: Buffer[] = [Buffer.from('PATCH')]
  for (const p of patches) {
    const rec = Buffer.alloc(5 + p.bytes.length)
    rec[0] = (p.offset >> 16) & 0xFF
    rec[1] = (p.offset >> 8) & 0xFF
    rec[2] = p.offset & 0xFF
    rec[3] = (p.bytes.length >> 8) & 0xFF
    rec[4] = p.bytes.length & 0xFF
    p.bytes.copy(rec, 5)
    chunks.push(rec)
  }
  chunks.push(Buffer.from('EOF'))
  return Buffer.concat(chunks)
}

export function createPatchGenerateHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, policyGuard, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof PatchGenerateInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const policyDecision = await policyGuard.checkPermission(
        { type: 'dynamic_execution', tool: TOOL_NAME, args: { patch_count: args.patches.length } },
        { sampleId: args.sample_id, timestamp: new Date().toISOString() }
      )
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(), operation: TOOL_NAME,
        sampleId: args.sample_id, decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
      })
      if (!policyDecision.allowed) {
        return { ok: false, errors: [policyDecision.reason || 'Patch generation denied by policy guard.'], metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME } }
      }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)
      const data = Buffer.from(await fs.readFile(samplePath))

      // Try to detect PE and parse sections for VA→offset mapping
      let imageBase = args.image_base ? parseHexAddr(args.image_base) : 0
      let sections: Array<{ va: number; rawOffset: number; rawSize: number; virtualSize: number }> = []
      const isPE = data.length > 0x40 && data[0] === 0x4D && data[1] === 0x5A

      if (isPE) {
        try {
          const parsed = parsePESections(data)
          if (!args.image_base) imageBase = parsed.imageBase
          sections = parsed.sections
        } catch {
          warnings.push('PE section parsing failed; treating addresses as file offsets')
        }
      }

      const appliedPatches: Array<{ offset: number; bytes: Buffer; comment?: string }> = []
      const patchedData = Buffer.from(data)

      for (const patch of args.patches) {
        const addr = parseHexAddr(patch.address)
        const fileOffset = sections.length > 0 ? vaToFileOffset(addr, imageBase, sections) : addr

        if (fileOffset < 0 || fileOffset >= data.length) {
          warnings.push(`Address ${patch.address} (offset ${fileOffset}) is out of bounds, skipped`)
          continue
        }

        let patchBytes: Buffer

        switch (patch.type) {
          case 'nop': {
            const size = patch.size ?? 1
            patchBytes = Buffer.alloc(size, NOP)
            break
          }
          case 'jmp_always': {
            const originalByte = data[fileOffset]
            if (COND_JUMPS_SHORT.has(originalByte)) {
              // Short Jcc → JMP SHORT, keep displacement
              patchBytes = Buffer.from([JMP_SHORT, data[fileOffset + 1]])
            } else if (data[fileOffset] === COND_JUMPS_NEAR_PREFIX &&
                       data[fileOffset + 1] >= COND_JUMPS_NEAR_RANGE[0] &&
                       data[fileOffset + 1] <= COND_JUMPS_NEAR_RANGE[1]) {
              // Near Jcc (0F 8x) → NOP + JMP NEAR (E9), keep 4-byte displacement
              patchBytes = Buffer.alloc(6)
              patchBytes[0] = NOP
              patchBytes[1] = JMP_NEAR
              data.copy(patchBytes, 2, fileOffset + 2, fileOffset + 6)
            } else {
              warnings.push(`${patch.address}: not a recognized conditional jump (byte: 0x${originalByte.toString(16)}), applying JMP SHORT`)
              patchBytes = Buffer.from([JMP_SHORT, data[fileOffset + 1]])
            }
            break
          }
          case 'invert_branch': {
            const byte0 = data[fileOffset]
            if (COND_JUMPS_SHORT.has(byte0)) {
              patchBytes = Buffer.from([byte0 ^ 0x01])
            } else if (data[fileOffset] === COND_JUMPS_NEAR_PREFIX &&
                       data[fileOffset + 1] >= COND_JUMPS_NEAR_RANGE[0] &&
                       data[fileOffset + 1] <= COND_JUMPS_NEAR_RANGE[1]) {
              patchBytes = Buffer.from([COND_JUMPS_NEAR_PREFIX, data[fileOffset + 1] ^ 0x01])
            } else {
              warnings.push(`${patch.address}: not a recognized conditional jump, skipped invert`)
              continue
            }
            break
          }
          case 'custom': {
            if (!patch.bytes) {
              warnings.push(`${patch.address}: custom patch requires 'bytes' field, skipped`)
              continue
            }
            patchBytes = Buffer.from(patch.bytes.replace(/\s/g, ''), 'hex')
            break
          }
          default:
            continue
        }

        patchBytes.copy(patchedData, fileOffset)
        appliedPatches.push({ offset: fileOffset, bytes: patchBytes, comment: patch.comment })
      }

      const artifacts: ArtifactRef[] = []

      // Generate IPS patch file
      if (args.output_format === 'ips' || args.output_format === 'both') {
        const ipsData = generateIPS(appliedPatches)
        const workspace = await workspaceManager.createWorkspace(args.sample_id)
        const ipsPath = path.join(workspace.reports, 'patch.ips')
        await fs.writeFile(ipsPath, ipsData)
        try {
          const artRef = await persistStaticAnalysisJsonArtifact!(
            workspaceManager, database, args.sample_id,
            'ips_patch', 'patch-ips', { ips_path: ipsPath, patch_count: appliedPatches.length }
          )
          if (artRef) artifacts.push(artRef)
        } catch { /* non-fatal */ }
      }

      // Generate patched binary
      let patchedSampleId: string | null = null
      if (args.output_format === 'patched_binary' || args.output_format === 'both') {
        const hash = crypto.createHash('sha256').update(patchedData).digest('hex')
        patchedSampleId = `sha256:${hash}`
        const patchedWorkspace = await workspaceManager.createWorkspace(patchedSampleId)
        const patchedPath = path.join(patchedWorkspace.original, 'sample.bin')
        await fs.writeFile(patchedPath, patchedData)

        try {
          database.insertSample({
            id: patchedSampleId,
            sha256: hash,
            md5: null,
            size: patchedData.length,
            file_type: sample.file_type,
            created_at: new Date().toISOString(),
            source: `patched_from:${args.sample_id}`,
          })
        } catch { /* may already exist */ }

        try {
          const artRef = await persistStaticAnalysisJsonArtifact!(
            workspaceManager, database, patchedSampleId,
            'patched_binary', 'patched-binary', {
              parent_sample_id: args.sample_id,
              patches: appliedPatches.length,
            }
          )
          if (artRef) artifacts.push(artRef)
        } catch { /* non-fatal */ }
      }

      const resultData = {
        patches_applied: appliedPatches.length,
        patches_requested: args.patches.length,
        patched_sample_id: patchedSampleId,
        patch_details: appliedPatches.map(p => ({
          file_offset: `0x${p.offset.toString(16)}`,
          bytes_hex: p.bytes.toString('hex'),
          size: p.bytes.length,
          comment: p.comment,
        })),
        image_base: `0x${imageBase.toString(16)}`,
      }

      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'patch_generation', 'patch-generate', resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
