import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { smartRecoverFunctionsFromPE } from '../pe-runtime-functions.js'
import { createStringsExtractHandler } from './strings-extract.js'
import { createRuntimeDetectHandler } from './runtime-detect.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { demangleRustSymbol, normalizeSymbolList, type DemangledSymbol } from './rust-demangle.js'

const TOOL_NAME = 'pe.symbols.recover'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

const cargoPathPattern = /(?:^|[\\/])cargo[\\/](?:registry|git)[\\/][^\\/]+[\\/](?<crate>[A-Za-z0-9_.-]+?)(?:-\d[\w.+-]*)?(?:[\\/]|$)/i

const rustMarkers = [
  'rust_panic',
  'core::panicking',
  'alloc::',
  'tokio::',
  'std::rt',
  'rustc',
  'panic_unwind',
] as const

export const peSymbolsRecoverInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_string_hints: z
    .number()
    .int()
    .min(20)
    .max(400)
    .optional()
    .default(120)
    .describe('Maximum strings inspected when deriving Rust/Go/C++ symbol hints'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

const recoveredSymbolSchema = z.object({
  address: z.string(),
  rva: z.number(),
  size: z.number(),
  recovered_name: z.string(),
  base_name: z.string(),
  original_candidate_name: z.string(),
  confidence: z.number(),
  language_hint: z.string().nullable(),
  name_strategy: z.string(),
  recovery_source: z.string(),
  is_entry_point: z.boolean(),
  is_exported: z.boolean(),
  export_name: z.string().optional(),
  crate_hints: z.array(z.string()),
  evidence: z.array(z.string()),
})

export const peSymbolsRecoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      machine: z.number(),
      machine_name: z.string(),
      image_base: z.number(),
      entry_point_rva: z.number(),
      primary_runtime: z.string().nullable(),
      runtime_hints: z.array(z.string()),
      crate_hints: z.array(z.string()),
      count: z.number(),
      symbols: z.array(recoveredSymbolSchema),
      warnings: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const peSymbolsRecoverToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover importable symbolic function names from PE runtime metadata such as .pdata / .xdata, exports, entry point, and language/runtime hints.',
  inputSchema: peSymbolsRecoverInputSchema,
  outputSchema: peSymbolsRecoverOutputSchema,
}

type StringsData = {
  strings?: Array<{
    offset: number
    string: string
    encoding: string
  }>
}

type RuntimeDetectData = {
  is_dotnet?: boolean
  suspected?: Array<{
    runtime: string
    confidence: number
    evidence: string[]
  }>
}

interface SymbolRecoverDependencies {
  stringsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  runtimeHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function normalizeSymbolBase(name: string): string {
  return name
    .replace(/[^A-Za-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_{2,}/g, '_')
    .toLowerCase() || 'recovered_function'
}

function extractCrateHints(strings: string[]): string[] {
  const crates = new Set<string>()
  for (const value of strings) {
    const cargoMatch = value.match(cargoPathPattern)
    const crate = cargoMatch?.groups?.crate?.trim()
    if (crate) {
      crates.add(crate.toLowerCase())
    }
  }
  return Array.from(crates).slice(0, 12)
}

function inferRuntimeHints(
  runtimeData: RuntimeDetectData | undefined,
  strings: string[],
  crateHints: string[]
): { primaryRuntime: string | null; runtimeHints: string[] } {
  const runtimeHints = new Set<string>()
  let primaryRuntime =
    runtimeData?.suspected
      ?.slice()
      .sort((left, right) => right.confidence - left.confidence)[0]?.runtime || null

  for (const suspected of runtimeData?.suspected || []) {
    runtimeHints.add(suspected.runtime)
  }

  if (crateHints.length > 0 || strings.some((value) => rustMarkers.some((marker) => value.includes(marker)))) {
    runtimeHints.add('rust')
    primaryRuntime = primaryRuntime || 'rust'
  }

  if (strings.some((value) => value.includes('Go build') || value.includes('go.buildid'))) {
    runtimeHints.add('go')
    primaryRuntime = primaryRuntime || 'go'
  }

  return {
    primaryRuntime,
    runtimeHints: Array.from(runtimeHints),
  }
}

function recoverSymbolName(options: {
  originalCandidateName: string
  rva: number
  isEntryPoint: boolean
  isExported: boolean
  exportName?: string
  runtimeHints: string[]
  crateHints: string[]
  unwindFlags: string[]
}): {
  recoveredName: string
  baseName: string
  strategy: string
  confidence: number
  languageHint: string | null
  evidence: string[]
} {
  const evidence: string[] = []
  let strategy = 'pdata_generic'
  let languageHint: string | null = null
  let baseName = normalizeSymbolBase(options.originalCandidateName)
  let confidence = 0.62

  if (options.isExported && options.exportName) {
    strategy = 'export_surface'
    baseName = normalizeSymbolBase(options.exportName)
    confidence = 0.94
    evidence.push(`Matched PE export ${options.exportName}`)
  } else if (options.isEntryPoint) {
    if (options.runtimeHints.includes('rust')) {
      strategy = 'rust_entry_point'
      baseName = 'rust_entry_point'
      confidence = 0.88
      languageHint = 'rust'
    } else if (options.runtimeHints.includes('go')) {
      strategy = 'go_entry_point'
      baseName = 'go_entry_point'
      confidence = 0.84
      languageHint = 'go'
    } else {
      strategy = 'entry_point'
      baseName = 'entry_point'
      confidence = 0.8
    }
    evidence.push('Matches PE entry point RVA')
  } else if (options.runtimeHints.includes('rust')) {
    languageHint = 'rust'
    if (options.unwindFlags.includes('EHANDLER') || options.unwindFlags.includes('UHANDLER')) {
      strategy = 'rust_unwind_runtime_function'
      baseName = 'rust_unwind_runtime_function'
      confidence = 0.78
      evidence.push(`Rust unwind flags observed: ${options.unwindFlags.join('|')}`)
    } else {
      strategy = 'rust_runtime_function'
      baseName = 'rust_runtime_function'
      confidence = 0.72
    }
    if (options.crateHints.length > 0) {
      evidence.push(`Rust crate hints: ${options.crateHints.slice(0, 3).join(', ')}`)
    }
  } else if (options.runtimeHints.includes('go')) {
    strategy = 'go_runtime_function'
    baseName = 'go_runtime_function'
    confidence = 0.7
    languageHint = 'go'
  } else if (options.unwindFlags.includes('CHAININFO')) {
    strategy = 'chained_unwind_runtime_function'
    baseName = 'chained_unwind_runtime_function'
    confidence = 0.7
    evidence.push('Unwind CHAININFO flag observed')
  } else {
    evidence.push('Recovered from PE exception directory (.pdata) runtime function entry')
  }

  const recoveredName = `${baseName}_${options.rva.toString(16).padStart(8, '0')}`
  return {
    recoveredName,
    baseName,
    strategy,
    confidence,
    languageHint,
    evidence,
  }
}

export function createPESymbolsRecoverHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: SymbolRecoverDependencies = {}
) {
  const stringsHandler =
    dependencies.stringsHandler || createStringsExtractHandler(workspaceManager, database, cacheManager)
  const runtimeHandler =
    dependencies.runtimeHandler || createRuntimeDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = peSymbolsRecoverInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          max_string_hints: input.max_string_hints,
        },
      })

      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          return {
            ok: true,
            data: cachedLookup.data,
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
            },
          }
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const recovery = smartRecoverFunctionsFromPE(samplePath)

      const [stringsResult, runtimeResult] = await Promise.all([
        stringsHandler({
          sample_id: input.sample_id,
          max_strings: input.max_string_hints,
          category_filter: 'all',
        }),
        runtimeHandler({
          sample_id: input.sample_id,
        }),
      ])

      const stringsData = (stringsResult.ok ? stringsResult.data : undefined) as StringsData | undefined
      const runtimeData = (runtimeResult.ok ? runtimeResult.data : undefined) as RuntimeDetectData | undefined
      const rawStrings = (stringsData?.strings || []).map((item) => item.string)
      const crateHints = extractCrateHints(rawStrings)
      const { primaryRuntime, runtimeHints } = inferRuntimeHints(runtimeData, rawStrings, crateHints)

      const symbols = recovery.functions.map((item) => {
        const unwindFlags = item.unwind?.flagNames || []
        const naming = recoverSymbolName({
          originalCandidateName: item.name,
          rva: item.rva,
          isEntryPoint: item.isEntryPoint,
          isExported: item.isExported,
          exportName: item.exportName,
          runtimeHints,
          crateHints,
          unwindFlags,
        })

        return {
          address: item.address,
          rva: item.rva,
          size: item.size,
          recovered_name: naming.recoveredName,
          base_name: naming.baseName,
          original_candidate_name: item.name,
          confidence: Math.min(0.98, Math.max(item.confidence, naming.confidence)),
          language_hint: naming.languageHint,
          name_strategy: naming.strategy,
          recovery_source: item.source,
          is_entry_point: item.isEntryPoint,
          is_exported: item.isExported,
          export_name: item.exportName,
          crate_hints: crateHints,
          evidence: Array.from(new Set([...item.evidence, ...naming.evidence])),
        }
      })

      const normalized = {
        machine: recovery.machine,
        machine_name: recovery.machineName,
        image_base: recovery.imageBase,
        entry_point_rva: recovery.entryPointRva,
        primary_runtime: primaryRuntime,
        runtime_hints: runtimeHints,
        crate_hints: crateHints,
        count: symbols.length,
        symbols,
        warnings: recovery.warnings,
      }

      await cacheManager.setCachedResult(cacheKey, normalized, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: normalized,
        warnings: recovery.warnings.length > 0 ? recovery.warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
