/**
 * vm.disasm.build MCP tool — build a custom disassembler from a VM's opcode table
 * and disassemble bytecode.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { buildDisassembler, disassemble, formatDisassembly } from '../vm/disassembler-builder.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'

const TOOL_NAME = 'vm.disasm.build'

export const vmDisasmBuildInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  bytecode_hex: z.string().optional().describe('Hex-encoded VM bytecode to disassemble'),
  bytecode_offset: z.number().optional().describe('Offset in sample file where VM bytecode starts'),
  bytecode_length: z.number().optional().describe('Length of bytecode to read from file'),
})

export const vmDisasmBuildOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmDisasmBuildToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a custom disassembler from a VM opcode table (extracted by vm.opcode.extract) and disassemble VM bytecode. Supports direct hex input or file offset.',
  inputSchema: vmDisasmBuildInputSchema,
  outputSchema: vmDisasmBuildOutputSchema,
}

export function createVmDisasmBuildHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmDisasmBuildInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load opcode table from previous analysis
    const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
    let opcodeTable = null

    if (Array.isArray(evidence)) {
      for (const entry of evidence) {
        if (entry.evidence_family === 'vm_opcode_table') {
          const data = typeof entry.result_json === 'string'
            ? JSON.parse(entry.result_json)
            : entry.result_json
          if (data?.opcode_table) {
            opcodeTable = data.opcode_table
            break
          }
        }
      }
    }

    if (!opcodeTable) {
      return {
        ok: false,
        errors: ['No opcode table found. Run vm.opcode.extract first.'],
      }
    }

    // Get bytecode
    let bytecodeBuffer: Buffer | null = null

    if (input.bytecode_hex) {
      bytecodeBuffer = Buffer.from(input.bytecode_hex.replace(/\s/g, ''), 'hex')
    } else if (input.bytecode_offset !== undefined) {
      const fs = await import('fs')
      try {
        const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
        if (!samplePath) {
          return { ok: false, errors: ['Sample file path not available'] }
        }
        const fd = fs.openSync(samplePath, 'r')
        const len = input.bytecode_length ?? 4096
        bytecodeBuffer = Buffer.alloc(len)
        fs.readSync(fd, bytecodeBuffer, 0, len, input.bytecode_offset)
        fs.closeSync(fd)
      } catch (e) {
        return { ok: false, errors: [`Failed to read bytecode from file: ${e}`] }
      }
    }

    if (!bytecodeBuffer) {
      return {
        ok: false,
        errors: ['No bytecode provided. Specify bytecode_hex or bytecode_offset.'],
      }
    }

    // Build disassembler and run
    const disasm = buildDisassembler(opcodeTable)
    const disasmResult = disassemble(bytecodeBuffer, disasm)
    const formatted = formatDisassembly(disasmResult)

    const result = {
      disassembly: formatted,
      instructions: disasmResult.instructions.map(i => ({
        address: i.address,
        opcode: i.opcode,
        mnemonic: i.mnemonic,
        operands: i.operands,
        length: i.length,
        raw_hex: bytecodeBuffer!.subarray(i.address, i.address + i.length).toString('hex'),
      })),
      total_instructions: disasmResult.instructions.length,
      coverage: disasmResult.coverage,
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'vm_disassembly', 'disassembly_result', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist disassembly artifact')
    }

    return {
      ok: true,
      data: result,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
