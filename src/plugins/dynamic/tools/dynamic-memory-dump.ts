/**
 * dynamic.memory.dump MCP tool — smart memory dump triggered by memory allocation/protection hooks.
 * Uses Frida to monitor VirtualAlloc/VirtualProtect and dump at strategic moments.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import path from 'path'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dynamic.memory.dump'

export const DynamicMemoryDumpInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  trigger: z.enum(['alloc_rwx', 'protect_rx', 'on_entry', 'timed']).optional().default('alloc_rwx')
    .describe('Dump trigger: alloc_rwx (RWX allocation), protect_rx (protection change to RX), on_entry (at EP), timed (after N ms)'),
  delay_ms: z.number().int().min(0).max(60000).optional().default(3000)
    .describe('For timed trigger, delay before dump in ms'),
  max_dumps: z.number().int().min(1).max(20).optional().default(5),
  timeout_sec: z.number().int().min(5).max(120).optional().default(30),
})

export const dynamicMemoryDumpToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Smart memory dump during execution. Hooks VirtualAlloc/VirtualProtect to detect unpacking ' +
    '(RWX allocation, W→RX protection changes) and auto-dump memory regions at strategic moments. ' +
    'Useful for extracting unpacked code from packed/encrypted binaries.',
  inputSchema: DynamicMemoryDumpInputSchema,
}

const FRIDA_DUMP_SCRIPT = `
var dumpCount = 0;
var maxDumps = %MAX_DUMPS%;
var trigger = '%TRIGGER%';
var delayMs = %DELAY_MS%;

function dumpRegion(base, size, reason) {
    if (dumpCount >= maxDumps) return;
    try {
        var data = base.readByteArray(Math.min(size, 0x100000)); // 1MB cap per dump
        send({ type: 'memory_dump', reason: reason, base: base.toString(),
               size: size, dump_index: dumpCount }, data);
        dumpCount++;
    } catch(e) {
        send({ type: 'dump_error', reason: reason, base: base.toString(), error: e.toString() });
    }
}

if (trigger === 'alloc_rwx' || trigger === 'protect_rx') {
    // Hook VirtualAlloc
    var pVA = Module.getExportByName('kernel32.dll', 'VirtualAlloc');
    if (pVA) {
        Interceptor.attach(pVA, {
            onEnter: function(args) {
                this.size = args[1].toInt32();
                this.protect = args[3].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.isNull() && trigger === 'alloc_rwx') {
                    // PAGE_EXECUTE_READWRITE = 0x40
                    if (this.protect === 0x40 || this.protect === 0x10) {
                        send({ type: 'alloc_detected', base: retval.toString(),
                               size: this.size, protect: this.protect });
                        // Delayed dump to catch written content
                        var base = retval; var size = this.size;
                        setTimeout(function() { dumpRegion(base, size, 'alloc_rwx'); }, 500);
                    }
                }
            }
        });
    }

    // Hook VirtualProtect
    var pVP = Module.getExportByName('kernel32.dll', 'VirtualProtect');
    if (pVP) {
        Interceptor.attach(pVP, {
            onEnter: function(args) {
                this.addr = args[0];
                this.size = args[1].toInt32();
                this.newProtect = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (trigger === 'protect_rx' && retval.toInt32() !== 0) {
                    // PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE = 0x10
                    if (this.newProtect === 0x20 || this.newProtect === 0x10 || this.newProtect === 0x40) {
                        send({ type: 'protect_detected', base: this.addr.toString(),
                               size: this.size, new_protect: this.newProtect });
                        dumpRegion(this.addr, this.size, 'protect_change_rx');
                    }
                }
            }
        });
    }
}

if (trigger === 'timed') {
    setTimeout(function() {
        Process.enumerateRanges('r-x').forEach(function(range) {
            if (range.size > 0x1000 && range.size < 0x1000000) {
                dumpRegion(ptr(range.base), range.size, 'timed_rx_region');
            }
        });
    }, delayMs);
}

send({ type: 'dump_hooks_installed', trigger: trigger, max_dumps: maxDumps });
`;

export function createDynamicMemoryDumpHandler(
  deps: PluginToolDeps
) {
  const { workspaceManager, database, config, policyGuard, resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath } = deps
  const pythonCmd = config?.workers?.frida?.path || config?.workers?.static?.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')
  return async (args: z.infer<typeof DynamicMemoryDumpInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const policyDecision = await policyGuard.checkPermission(
        { type: 'dynamic_execution', tool: TOOL_NAME, args: { trigger: args.trigger } },
        { sampleId: args.sample_id, timestamp: new Date().toISOString() }
      )
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(), operation: TOOL_NAME,
        sampleId: args.sample_id, decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
      })
      if (!policyDecision.allowed) {
        return { ok: false, errors: [policyDecision.reason || 'Memory dump denied by policy guard.'], metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME } }
      }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const script = FRIDA_DUMP_SCRIPT
        .replace('%MAX_DUMPS%', String(args.max_dumps))
        .replace('%TRIGGER%', args.trigger)
        .replace('%DELAY_MS%', String(args.delay_ms))

      // Write the script, then delegate to frida worker
      const workspace = await workspaceManager.createWorkspace(args.sample_id)
      const fs = await import('fs/promises')
      const scriptPath = path.join(workspace.reports, 'memory_dump_hook.js')
      await fs.writeFile(scriptPath, script, 'utf-8')

      // Call frida worker to execute
      const workerPath = resolvePackagePath!('workers', 'frida_worker.py')

      const result = await new Promise<Record<string, unknown>>((resolve, reject) => {
        const proc = spawn(pythonCmd, [workerPath], {
          stdio: ['pipe', 'pipe', 'pipe'],
          timeout: args.timeout_sec * 1000 + 5000,
        })
        let stdout = ''
        let stderr = ''
        proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
        proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
        proc.on('close', (code) => {
          if (code !== 0 && !stdout.trim()) {
            reject(new Error(`Frida worker exited ${code}: ${stderr.slice(0, 500)}`))
            return
          }
          try { resolve(JSON.parse(stdout.trim())) }
          catch { resolve({ ok: false, error: 'Parse error', stderr: stderr.slice(0, 500) }) }
        })
        proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
        proc.stdin.write(JSON.stringify({
          action: 'inject_script',
          target: samplePath,
          script_path: scriptPath,
          timeout: args.timeout_sec,
          spawn: true,
        }) + '\n')
        proc.stdin.end()
      })

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact?.(
          workspaceManager, database, args.sample_id,
          'memory_dump', 'memory-dump-hook', {
            trigger: args.trigger,
            script_path: scriptPath,
            result,
          }
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: Boolean(result.ok),
        data: {
          ...result,
          trigger: args.trigger,
          script_path: scriptPath,
        },
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
