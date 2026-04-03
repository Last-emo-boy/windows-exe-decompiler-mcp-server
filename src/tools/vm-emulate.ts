/**
 * vm.emulate MCP tool — concrete/symbolic execution of VM bytecode.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { emulate, type EmulateOptions } from '../vm/vm-emulator.js'

const TOOL_NAME = 'vm.emulate'

export const vmEmulateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  bytecode_hex: z.string().describe('Hex-encoded VM bytecode to emulate'),
  initial_registers: z
    .record(z.number())
    .optional()
    .describe('Initial register values (e.g. {"r0": 1234, "r1": 0})'),
  max_steps: z
    .number()
    .int()
    .min(1)
    .max(100000)
    .optional()
    .default(10000)
    .describe('Maximum emulation steps'),
  symbolic: z
    .boolean()
    .optional()
    .default(false)
    .describe('Enable symbolic execution mode'),
  bit_width: z
    .number()
    .int()
    .optional()
    .default(32)
    .describe('Register bit width (8, 16, 32, 64)'),
})

export const vmEmulateOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmEmulateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Emulate VM bytecode with concrete or symbolic execution. Requires a previously extracted opcode table. Produces an execution trace with register states per step and extracted constraints.',
  inputSchema: vmEmulateInputSchema,
  outputSchema: vmEmulateOutputSchema,
}

export function createVmEmulateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmEmulateInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load opcode table
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

    const bytecodeBuffer = Buffer.from(input.bytecode_hex.replace(/\s/g, ''), 'hex')

    // Build emulation options
    const initialRegs: Record<string, bigint | string> = {}
    if (input.initial_registers) {
      for (const [reg, val] of Object.entries(input.initial_registers)) {
        initialRegs[reg] = input.symbolic ? reg : BigInt(val)
      }
    }

    const options: EmulateOptions = {
      mode: input.symbolic ? 'symbolic' : 'concrete',
      maxSteps: input.max_steps,
      initialRegisters: Object.keys(initialRegs).length > 0 ? initialRegs : undefined,
      bitWidth: input.bit_width,
    }

    // Run emulation
    const emulationResult = emulate(bytecodeBuffer, opcodeTable, options)

    const result = {
      steps_executed: emulationResult.trace.length,
      termination_reason: emulationResult.terminationReason,
      final_registers: emulationResult.finalRegisters,
      constraints_extracted: emulationResult.constraints.length,
      constraints: emulationResult.constraints.map(c => ({
        left: c.leftExpr,
        operator: c.operator,
        right: c.rightValue,
        source_pc: c.sourcePC,
      })),
      trace_summary: emulationResult.trace.slice(0, 100).map(s => ({
        pc: s.pc,
        mnemonic: s.mnemonic,
        operands: s.operands,
      })),
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager, database, input.sample_id,
        'vm_emulation', 'emulation_result', result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist emulation artifact')
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
