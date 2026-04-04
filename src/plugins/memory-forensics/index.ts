/**
 * Memory Forensics Plugin
 *
 * Integrates with Volatility 3 for memory dump analysis.
 * Provides tools for process listing, DLL extraction, registry hive parsing,
 * and memory-resident malware detection from memory dumps.
 */

import { execFile, execFileSync } from 'child_process'
import { promisify } from 'util'
import type { Plugin, ToolResult, PluginToolDeps } from '../sdk.js'

const execFileAsync = promisify(execFile)

function getVolatilityPath(): string {
  return process.env.VOLATILITY3_PATH || process.env.VOL3_PATH || 'vol3'
}

async function runVol3(args: string[], timeout = 120_000): Promise<string> {
  const vol3 = getVolatilityPath()
  const { stdout } = await execFileAsync(vol3, args, {
    timeout,
    maxBuffer: 50 * 1024 * 1024,
    env: { ...process.env },
  })
  return stdout
}

async function resolveDumpPath(args: { sample_id?: string; dump_path?: string }, deps: PluginToolDeps): Promise<string> {
  if (args.dump_path) return args.dump_path
  if (!args.sample_id) throw new Error('Either sample_id or dump_path must be provided')

  const wm = deps.workspaceManager as any
  if (typeof wm.getSamplePath === 'function') {
    return wm.getSamplePath(args.sample_id)
  }
  throw new Error('Cannot resolve sample path — provide dump_path directly')
}

function tryParseJson(text: string): Record<string, unknown> {
  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    return { raw_output: text }
  }
}

const memoryForensicsPlugin: Plugin = {
  id: 'memory-forensics',
  name: 'Memory Forensics (Volatility 3)',
  description: 'Memory dump analysis using Volatility 3 — process listing, DLL extraction, registry analysis, and memory-resident malware detection.',
  version: '1.0.0',
  configSchema: [
    { envVar: 'VOLATILITY3_PATH', description: 'Path to Volatility 3 (vol3) executable', required: true },
    { envVar: 'VOL3_SYMBOL_PATH', description: 'Path to Volatility 3 symbol tables', required: false },
  ],

  check() {
    const vol3 = getVolatilityPath()
    try {
      execFileSync(vol3, ['--help'], { timeout: 5000, stdio: 'pipe' })
      return true
    } catch {
      throw new Error(`Volatility 3 (${vol3}) not found. Install with: pip install volatility3, or set VOLATILITY3_PATH env var.`)
    }
  },

  register(server, deps): string[] {
    const tools: string[] = []

    // ── memory-forensics.pslist ──────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.pslist',
        description: 'List processes from a memory dump using Volatility 3.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string', description: 'Sample ID of the memory dump' },
            dump_path: { type: 'string', description: 'Direct path to memory dump file (alternative to sample_id)' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3(['-f', dumpPath, 'windows.pslist.PsList', '--output', 'json'])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.pslist')

    // ── memory-forensics.dlllist ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.dlllist',
        description: 'List loaded DLLs from a memory dump.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string' },
            dump_path: { type: 'string' },
            pid: { type: 'number', description: 'Filter by Process ID' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string; pid?: number }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.dlllist.DllList', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.dlllist')

    // ── memory-forensics.malfind ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.malfind',
        description: 'Detect injected code and suspicious memory regions in a memory dump.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string' },
            dump_path: { type: 'string' },
            pid: { type: 'number', description: 'Filter by Process ID' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string; pid?: number }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.malfind.Malfind', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.malfind')

    // ── memory-forensics.netscan ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.netscan',
        description: 'Scan for network connections in a memory dump.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string' },
            dump_path: { type: 'string' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3(['-f', dumpPath, 'windows.netscan.NetScan', '--output', 'json'])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.netscan')

    // ── memory-forensics.hivelist ────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.hivelist',
        description: 'List registry hives found in a memory dump.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string' },
            dump_path: { type: 'string' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3(['-f', dumpPath, 'windows.registry.hivelist.HiveList', '--output', 'json'])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.hivelist')

    // ── memory-forensics.cmdline ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.cmdline',
        description: 'Extract command-line arguments for all processes in a memory dump.',
        inputSchema: {
          type: 'object',
          properties: {
            sample_id: { type: 'string' },
            dump_path: { type: 'string' },
            pid: { type: 'number', description: 'Filter by Process ID' },
          },
        } as any,
      },
      async (args: { sample_id?: string; dump_path?: string; pid?: number }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.cmdline.CmdLine', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.cmdline')

    return tools
  },
}

export default memoryForensicsPlugin
