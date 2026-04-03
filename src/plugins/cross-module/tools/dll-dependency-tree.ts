/**
 * dll.dependency.tree MCP tool — Build a dependency tree for a binary,
 * resolving which DLLs/SOs are in the sample set vs system/external.
 * Highlights potential DLL side-loading / hijacking opportunities.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'dll.dependency.tree'

export const DllDependencyTreeInputSchema = z.object({
  sample_id: z.string().describe('Root sample ID (format: sha256:<hex>)'),
  known_sample_ids: z
    .array(z.string())
    .optional()
    .describe('Additional sample IDs for DLLs that may be dependencies'),
})

export const dllDependencyTreeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a dependency tree for a binary starting from its import table. ' +
    'Classifies each dependency as known-system, known-sample (in your collection), ' +
    'or unknown/suspicious. Flags potential DLL side-loading vectors.',
  inputSchema: DllDependencyTreeInputSchema,
}

const KNOWN_SYSTEM_DLLS = new Set([
  'kernel32.dll', 'ntdll.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll',
  'ole32.dll', 'oleaut32.dll', 'shell32.dll', 'comctl32.dll', 'comdlg32.dll',
  'ws2_32.dll', 'wsock32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll',
  'msvcrt.dll', 'msvcr100.dll', 'msvcr110.dll', 'msvcr120.dll', 'msvcr140.dll',
  'vcruntime140.dll', 'ucrtbase.dll', 'msvcp140.dll',
  'crypt32.dll', 'bcrypt.dll', 'ncrypt.dll', 'wintrust.dll',
  'rpcrt4.dll', 'secur32.dll', 'shlwapi.dll', 'version.dll', 'iphlpapi.dll',
  'dnsapi.dll', 'netapi32.dll', 'psapi.dll', 'dbghelp.dll', 'imagehlp.dll',
  'setupapi.dll', 'cfgmgr32.dll', 'devobj.dll', 'wtsapi32.dll',
  'mpr.dll', 'userenv.dll', 'sspicli.dll', 'cryptbase.dll',
  'kernelbase.dll', 'api-ms-win-core-synch-l1-1-0.dll',
  'api-ms-win-core-processthreads-l1-1-0.dll',
  'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
  'ld-linux-x86-64.so.2', 'libstdc++.so.6', 'libgcc_s.so.1',
])

export function createDllDependencyTreeHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof DllDependencyTreeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Build a map of known sample module names → sample_id
      const knownModules = new Map<string, string>()
      const allSampleIds = [args.sample_id, ...(args.known_sample_ids ?? [])]
      for (const sid of allSampleIds) {
        const s = database.findSample(sid)
        if (!s) continue
        const name = s.file_type ?? sid.replace('sha256:', '').slice(0, 12)
        if (name) knownModules.set(name.toLowerCase(), sid)
      }

      // Extract imports from root sample
      const imports: Array<{ dll: string; function_count: number; functions: string[] }> = []
      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const family = entry.evidence_family ?? ''

            if (family === 'pe_imports' || family === 'elf_imports') {
              const impEntries = data?.data?.imports ?? data?.imports ?? []
              const grouped = new Map<string, string[]>()
              for (const imp of impEntries) {
                if (imp.dll && imp.functions) {
                  const dll = imp.dll.toLowerCase()
                  grouped.set(dll, (imp.functions as Array<{ name?: string }>).map((f) => f.name ?? 'unknown'))
                } else if (imp.dll && (imp.name || imp.function_name)) {
                  const dll = imp.dll.toLowerCase()
                  const existing = grouped.get(dll) ?? []
                  existing.push(imp.name ?? imp.function_name)
                  grouped.set(dll, existing)
                }
              }
              for (const [dll, fns] of grouped) {
                imports.push({ dll, function_count: fns.length, functions: fns })
              }
            }
          } catch { /* skip */ }
        }
      }

      // Classify dependencies
      interface DepNode {
        dll: string
        classification: 'system' | 'known_sample' | 'unknown'
        sample_id?: string
        function_count: number
        sideload_risk: boolean
        functions: string[]
      }

      const deps_list: DepNode[] = []
      const unknownDlls: string[] = []

      for (const imp of imports) {
        const dllLower = imp.dll.toLowerCase()
        const isSystem = KNOWN_SYSTEM_DLLS.has(dllLower) || dllLower.startsWith('api-ms-win-')
        const knownSampleId = knownModules.get(dllLower)

        const classification = isSystem ? 'system' : knownSampleId ? 'known_sample' : 'unknown'

        const sideloadRisk = !isSystem && !dllLower.includes('\\') && !dllLower.includes('/')

        if (classification === 'unknown') unknownDlls.push(imp.dll)

        deps_list.push({
          dll: imp.dll,
          classification,
          sample_id: knownSampleId,
          function_count: imp.function_count,
          sideload_risk: sideloadRisk,
          functions: imp.functions.slice(0, 30),
        })
      }

      const resultData = {
        sample_id: args.sample_id,
        total_dependencies: deps_list.length,
        system_deps: deps_list.filter((d) => d.classification === 'system').length,
        known_sample_deps: deps_list.filter((d) => d.classification === 'known_sample').length,
        unknown_deps: deps_list.filter((d) => d.classification === 'unknown').length,
        sideload_candidates: deps_list.filter((d) => d.sideload_risk).map((d) => d.dll),
        dependencies: deps_list.sort((a, b) => {
          const order = { unknown: 0, known_sample: 1, system: 2 }
          return order[a.classification] - order[b.classification]
        }),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id,
          'dll_dependency_tree', 'dll-dependency-tree', resultData
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
