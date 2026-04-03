/**
 * debug.session.breakpoint MCP tool â€?manage breakpoints in a debug session.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { getDebugSessionManager } from '../../../debug/debug-session-state.js'

const TOOL_NAME = 'debug.session.breakpoint'

export const DebugSessionBreakpointInputSchema = z.object({
  session_id: z.string().describe('Debug session ID'),
  action: z.enum(['add', 'remove', 'list']).describe('Breakpoint action'),
  address: z.string().optional().describe('Address or symbol for add (e.g., "0x401000" or "main")'),
  condition: z.string().optional().describe('Breakpoint condition expression'),
  breakpoint_id: z.string().optional().describe('Breakpoint ID for remove action'),
})

export const DebugSessionBreakpointOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const debugSessionBreakpointToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Manage breakpoints in a debug session: add (by address/symbol/condition), remove, or list all active breakpoints.',
  inputSchema: DebugSessionBreakpointInputSchema,
  outputSchema: DebugSessionBreakpointOutputSchema,
}

export function createDebugSessionBreakpointHandler(deps: PluginToolDeps) {
  return async (args: z.infer<typeof DebugSessionBreakpointInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const mgr = getDebugSessionManager()
      const session = mgr.getSession(args.session_id)
      if (!session) {
        return { ok: false, errors: [`Session not found: ${args.session_id}`] }
      }
      mgr.touch(args.session_id)

      switch (args.action) {
        case 'add': {
          if (!args.address) {
            return { ok: false, errors: ['address required for add action'] }
          }
          let cmd = `-break-insert ${args.address}`
          if (args.condition) {
            cmd = `-break-insert -c "${args.condition}" ${args.address}`
          }
          const resp = await session.gdb.command(cmd)
          const bkptId = String((resp.payload as Record<string, unknown>).bkpt
            ? ((resp.payload as Record<string, Record<string, unknown>>).bkpt.number || session.breakpoints.length + 1)
            : session.breakpoints.length + 1)
          
          const bp = {
            id: bkptId,
            address: args.address,
            symbol: args.address,
            condition: args.condition,
            hit_count: 0,
          }
          session.breakpoints.push(bp)
          session.history.push({
            timestamp: new Date().toISOString(),
            action: 'breakpoint_add',
            detail: { breakpoint: bp },
          })

          return {
            ok: true,
            data: { breakpoint: bp, total_breakpoints: session.breakpoints.length },
            metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
          }
        }
        case 'remove': {
          if (!args.breakpoint_id) {
            return { ok: false, errors: ['breakpoint_id required for remove action'] }
          }
          await session.gdb.command(`-break-delete ${args.breakpoint_id}`)
          session.breakpoints = session.breakpoints.filter((b) => b.id !== args.breakpoint_id)
          session.history.push({
            timestamp: new Date().toISOString(),
            action: 'breakpoint_remove',
            detail: { breakpoint_id: args.breakpoint_id },
          })

          return {
            ok: true,
            data: { removed: args.breakpoint_id, total_breakpoints: session.breakpoints.length },
            metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
          }
        }
        case 'list': {
          return {
            ok: true,
            data: {
              breakpoints: session.breakpoints,
              total: session.breakpoints.length,
            },
            metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
          }
        }
        default:
          return { ok: false, errors: [`Unknown action: ${args.action}`] }
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
