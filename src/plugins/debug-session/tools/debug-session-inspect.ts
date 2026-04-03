/**
 * debug.session.inspect MCP tool â€?inspect registers, memory, stack, disassembly.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'

const TOOL_NAME = 'debug.session.inspect'

export const DebugSessionInspectInputSchema = z.object({
  session_id: z.string().describe('Debug session ID'),
  target: z
    .enum(['registers', 'memory', 'stack', 'disasm'])
    .describe('What to inspect'),
  address: z
    .string()
    .optional()
    .describe('Memory address for memory/disasm targets (e.g., "0x401000")'),
  length: z
    .number()
    .int()
    .min(1)
    .max(4096)
    .optional()
    .default(256)
    .describe('Number of bytes for memory read (max 4096)'),
  count: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .default(20)
    .describe('Number of stack frames or disasm instructions'),
})

export const DebugSessionInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inspect debug session state: registers, memory (up to 4096 bytes), stack frames (up to 20), or disassembly window.',
  inputSchema: DebugSessionInspectInputSchema,
  outputSchema: DebugSessionInspectOutputSchema,
}

export function createDebugSessionInspectHandler(deps: PluginToolDeps) {
  return async (args: z.infer<typeof DebugSessionInspectInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const mgr = getDebugSessionManager()
      const session = mgr.getSession(args.session_id)
      if (!session) {
        return { ok: false, errors: [`Session not found: ${args.session_id}`] }
      }
      mgr.touch(args.session_id)

      let data: Record<string, unknown>

      switch (args.target) {
        case 'registers': {
          const resp = await session.gdb.command('-data-list-register-values x')
          data = { target: 'registers', ...resp.payload }
          break
        }
        case 'memory': {
          if (!args.address) {
            return { ok: false, errors: ['address required for memory inspection'] }
          }
          const resp = await session.gdb.command(
            `-data-read-memory-bytes ${args.address} ${args.length}`
          )
          data = { target: 'memory', address: args.address, length: args.length, ...resp.payload }
          break
        }
        case 'stack': {
          const maxFrames = Math.min(args.count, 20)
          const resp = await session.gdb.command(`-stack-list-frames 0 ${maxFrames - 1}`)
          data = { target: 'stack', max_frames: maxFrames, ...resp.payload }
          break
        }
        case 'disasm': {
          if (!args.address) {
            return { ok: false, errors: ['address required for disassembly inspection'] }
          }
          const numInsns = Math.min(args.count, 100)
          // -data-disassemble -s ADDR -e ADDR+N -- 0
          const endAddr = `${args.address}+${numInsns * 16}`
          const resp = await session.gdb.command(
            `-data-disassemble -s ${args.address} -e ${endAddr} -- 0`
          )
          data = { target: 'disasm', address: args.address, ...resp.payload }
          break
        }
        default:
          return { ok: false, errors: [`Unknown target: ${args.target}`] }
      }

      session.history.push({
        timestamp: new Date().toISOString(),
        action: `inspect_${args.target}`,
        detail: { address: args.address },
      })

      return {
        ok: true,
        data,
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
