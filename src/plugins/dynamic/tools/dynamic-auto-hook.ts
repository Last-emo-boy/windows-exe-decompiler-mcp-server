/**
 * dynamic.auto.hook MCP tool — automatically generate Frida hook scripts
 * based on static capability triage results.
 * Bridges static analysis → dynamic instrumentation.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dynamic.auto.hook'

// Capability → API hook mapping
const CAPABILITY_HOOKS: Record<string, Array<{ api: string; module: string; reason: string }>> = {
  'file_manipulation': [
    { api: 'CreateFileA', module: 'kernel32', reason: 'File creation/open' },
    { api: 'CreateFileW', module: 'kernel32', reason: 'File creation/open (wide)' },
    { api: 'WriteFile', module: 'kernel32', reason: 'File write' },
    { api: 'ReadFile', module: 'kernel32', reason: 'File read' },
    { api: 'DeleteFileA', module: 'kernel32', reason: 'File deletion' },
    { api: 'DeleteFileW', module: 'kernel32', reason: 'File deletion (wide)' },
  ],
  'registry_manipulation': [
    { api: 'RegOpenKeyExA', module: 'advapi32', reason: 'Registry open' },
    { api: 'RegOpenKeyExW', module: 'advapi32', reason: 'Registry open (wide)' },
    { api: 'RegSetValueExA', module: 'advapi32', reason: 'Registry write' },
    { api: 'RegSetValueExW', module: 'advapi32', reason: 'Registry write (wide)' },
    { api: 'RegQueryValueExA', module: 'advapi32', reason: 'Registry read' },
  ],
  'process_injection': [
    { api: 'OpenProcess', module: 'kernel32', reason: 'Process handle acquisition' },
    { api: 'VirtualAllocEx', module: 'kernel32', reason: 'Remote memory allocation' },
    { api: 'WriteProcessMemory', module: 'kernel32', reason: 'Remote memory write' },
    { api: 'CreateRemoteThread', module: 'kernel32', reason: 'Remote thread creation' },
    { api: 'NtQueueApcThread', module: 'ntdll', reason: 'APC injection' },
  ],
  'network_communication': [
    { api: 'InternetOpenA', module: 'wininet', reason: 'Internet session' },
    { api: 'InternetConnectA', module: 'wininet', reason: 'Server connection' },
    { api: 'HttpOpenRequestA', module: 'wininet', reason: 'HTTP request' },
    { api: 'HttpSendRequestA', module: 'wininet', reason: 'HTTP send' },
    { api: 'WSAStartup', module: 'ws2_32', reason: 'Winsock init' },
    { api: 'connect', module: 'ws2_32', reason: 'Socket connect' },
    { api: 'send', module: 'ws2_32', reason: 'Socket send' },
    { api: 'recv', module: 'ws2_32', reason: 'Socket receive' },
  ],
  'cryptography': [
    { api: 'CryptAcquireContextA', module: 'advapi32', reason: 'Crypto context' },
    { api: 'CryptHashData', module: 'advapi32', reason: 'Hash computation' },
    { api: 'CryptEncrypt', module: 'advapi32', reason: 'Encryption' },
    { api: 'CryptDecrypt', module: 'advapi32', reason: 'Decryption' },
    { api: 'BCryptOpenAlgorithmProvider', module: 'bcrypt', reason: 'BCrypt algorithm' },
  ],
  'privilege_escalation': [
    { api: 'AdjustTokenPrivileges', module: 'advapi32', reason: 'Token privilege adjustment' },
    { api: 'OpenProcessToken', module: 'advapi32', reason: 'Process token' },
    { api: 'ImpersonateLoggedOnUser', module: 'advapi32', reason: 'Impersonation' },
  ],
  'anti_debugging': [
    { api: 'IsDebuggerPresent', module: 'kernel32', reason: 'Debugger check' },
    { api: 'CheckRemoteDebuggerPresent', module: 'kernel32', reason: 'Remote debugger check' },
    { api: 'NtQueryInformationProcess', module: 'ntdll', reason: 'Process info query (anti-debug)' },
    { api: 'OutputDebugStringA', module: 'kernel32', reason: 'Debug output' },
  ],
  'persistence': [
    { api: 'CreateServiceA', module: 'advapi32', reason: 'Service creation' },
    { api: 'CreateServiceW', module: 'advapi32', reason: 'Service creation (wide)' },
    { api: 'RegSetValueExA', module: 'advapi32', reason: 'Registry persistence' },
    { api: 'SHGetFolderPathA', module: 'shell32', reason: 'Startup folder path' },
  ],
  'memory_manipulation': [
    { api: 'VirtualAlloc', module: 'kernel32', reason: 'Memory allocation' },
    { api: 'VirtualProtect', module: 'kernel32', reason: 'Memory protection change' },
    { api: 'NtAllocateVirtualMemory', module: 'ntdll', reason: 'NT memory allocation' },
  ],
}

export const DynamicAutoHookInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  capabilities: z.array(z.string()).optional().describe('Override detected capabilities for hook generation'),
  max_hooks: z.number().int().min(1).max(100).optional().default(30),
})

export const dynamicAutoHookToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Automatically generate Frida hook scripts based on static capability triage. ' +
    'Maps detected capabilities (file_manipulation, network_communication, etc.) to ' +
    'relevant API hooks with argument logging. Output can be directly used with frida.script.inject.',
  inputSchema: DynamicAutoHookInputSchema,
}

function generateFridaScript(hooks: Array<{ api: string; module: string; reason: string }>): string {
  const lines: string[] = [
    '// Auto-generated Frida hook script',
    '// Generated by dynamic.auto.hook MCP tool',
    '',
  ]

  for (const hook of hooks) {
    lines.push(`// ${hook.reason}`)
    lines.push(`try {`)
    lines.push(`  var p_${hook.api} = Module.getExportByName('${hook.module}.dll', '${hook.api}');`)
    lines.push(`  if (p_${hook.api}) {`)
    lines.push(`    Interceptor.attach(p_${hook.api}, {`)
    lines.push(`      onEnter: function(args) {`)
    lines.push(`        send({ type: 'api_call', api: '${hook.api}', module: '${hook.module}',`)
    lines.push(`          arg0: args[0] ? args[0].toString() : null,`)
    lines.push(`          arg1: args[1] ? args[1].toString() : null,`)
    lines.push(`          tid: Process.getCurrentThreadId(),`)
    lines.push(`          timestamp: Date.now() });`)
    lines.push(`      },`)
    lines.push(`      onLeave: function(retval) {`)
    lines.push(`        send({ type: 'api_return', api: '${hook.api}', retval: retval.toString() });`)
    lines.push(`      }`)
    lines.push(`    });`)
    lines.push(`  }`)
    lines.push(`} catch(e) { /* ${hook.api} not found */ }`)
    lines.push('')
  }

  lines.push(`send({ type: 'hooks_installed', count: ${hooks.length} });`)
  return lines.join('\n')
}

export function createDynamicAutoHookHandler(
  deps: PluginToolDeps
) {
  const { workspaceManager, database, policyGuard, persistStaticAnalysisJsonArtifact } = deps
  return async (args: z.infer<typeof DynamicAutoHookInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const policyDecision = await policyGuard.checkPermission(
        { type: 'dynamic_execution', tool: TOOL_NAME, args: { capabilities: args.capabilities } },
        { sampleId: args.sample_id, timestamp: new Date().toISOString() }
      )
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(), operation: TOOL_NAME,
        sampleId: args.sample_id, decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
      })
      if (!policyDecision.allowed) {
        return { ok: false, errors: [policyDecision.reason || 'Auto-hook generation denied by policy guard.'], metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME } }
      }

      let capabilities = args.capabilities ?? []

      // Auto-detect capabilities from existing triage results
      if (capabilities.length === 0) {
        const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            if (entry.evidence_family === 'capability_triage' || entry.evidence_family === 'static_triage') {
              try {
                const data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
                const caps = data?.capabilities ?? data?.data?.capabilities ?? data?.data?.capability_categories ?? []
                for (const cap of caps) {
                  const name = typeof cap === 'string' ? cap : (cap.name ?? cap.category ?? '')
                  if (name) capabilities.push(name.toLowerCase().replace(/[\s-]/g, '_'))
                }
              } catch { /* */ }
            }
          }
        }

        if (capabilities.length === 0) {
          warnings.push('No capability triage results found. Run static.capability.triage first for targeted hooks.')
          // Fallback: generate common hooks
          capabilities = ['file_manipulation', 'network_communication', 'memory_manipulation']
        }
      }

      // Map capabilities to API hooks
      const selectedHooks: Array<{ api: string; module: string; reason: string; capability: string }> = []
      const seenApis = new Set<string>()

      for (const cap of capabilities) {
        const hookDefs = CAPABILITY_HOOKS[cap]
        if (!hookDefs) {
          warnings.push(`Unknown capability "${cap}", skipped`)
          continue
        }
        for (const hook of hookDefs) {
          if (!seenApis.has(hook.api) && selectedHooks.length < args.max_hooks) {
            seenApis.add(hook.api)
            selectedHooks.push({ ...hook, capability: cap })
          }
        }
      }

      const scriptContent = generateFridaScript(selectedHooks)

      // Persist the generated script as an artifact
      const workspace = await workspaceManager.createWorkspace(args.sample_id)
      const fs = await import('fs/promises')
      const path = await import('path')
      const scriptPath = path.join(workspace.reports, 'auto_hook.js')
      await fs.writeFile(scriptPath, scriptContent, 'utf-8')

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact?.(
          workspaceManager, database, args.sample_id,
          'dynamic_auto_hook', 'auto-hook', {
            capabilities_matched: capabilities,
            hooks_count: selectedHooks.length,
            hooks: selectedHooks,
            script_path: scriptPath,
          }
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: {
          capabilities_detected: capabilities,
          hooks_generated: selectedHooks.length,
          hooks: selectedHooks,
          script_path: scriptPath,
          script_preview: scriptContent.slice(0, 2000),
          next_steps: [
            `Inject the script: frida.script.inject(sample_id='${args.sample_id}', script_path='${scriptPath}')`,
            `Or capture trace: frida.trace.capture(sample_id='${args.sample_id}')`,
          ],
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
