import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js'
import { createRuntimeDetectHandler } from './runtime-detect.js'
import { createStringsExtractHandler } from './strings-extract.js'
import { createCodeFunctionsSmartRecoverHandler } from './code-functions-smart-recover.js'
import { createPESymbolsRecoverHandler } from './pe-symbols-recover.js'
import { buildLibraryProfile } from '../workflows/triage.js'

const TOOL_NAME = 'rust_binary.analyze'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000

const LIBRARY_HINT_PATTERNS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'tokio', patterns: [/\btokio\b/i] },
  { name: 'goblin', patterns: [/\bgoblin\b/i] },
  { name: 'iced-x86', patterns: [/\biced[-_]?x86\b/i] },
  { name: 'clap', patterns: [/\bclap\b/i] },
  { name: 'sysinfo', patterns: [/\bsysinfo\b/i] },
  { name: 'reqwest', patterns: [/\breqwest\b/i] },
  { name: 'serde', patterns: [/\bserde\b/i] },
  { name: 'mio', patterns: [/\bmio\b/i] },
  { name: 'pelite', patterns: [/\bpelite\b/i] },
  { name: 'object', patterns: [/\bobject\b/i] },
  { name: 'winapi', patterns: [/\bwinapi\b/i] },
  { name: 'ntapi', patterns: [/\bntapi\b/i] },
  { name: 'windows-sys', patterns: [/\bwindows[-_]?sys\b/i] },
]

const RustLibraryProfileSchema = z.object({
  ecosystems: z.array(z.string()),
  top_crates: z.array(z.string()),
  notable_libraries: z.array(z.string()),
  evidence: z.array(z.string()),
})

export const rustBinaryAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_strings: z
    .number()
    .int()
    .min(40)
    .max(400)
    .optional()
    .default(160)
    .describe('Maximum strings inspected for Rust crate, panic, and async/runtime markers'),
  max_symbol_preview: z
    .number()
    .int()
    .min(1)
    .max(24)
    .optional()
    .default(8)
    .describe('Maximum recovered symbols returned in the preview'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export const RustBinaryAnalyzeDataSchema = z.object({
  sample_id: z.string(),
  suspected_rust: z.boolean(),
  confidence: z.number().min(0).max(1),
  primary_runtime: z.string().nullable(),
  runtime_hints: z.array(z.string()),
  cargo_paths: z.array(z.string()),
  rust_markers: z.array(z.string()),
  async_runtime_markers: z.array(z.string()),
  panic_markers: z.array(z.string()),
  crate_hints: z.array(z.string()),
  library_profile: RustLibraryProfileSchema.optional(),
  binary_profile: BinaryRoleProfileDataSchema.optional(),
  recovered_function_count: z.number().int().nonnegative(),
  recovered_function_strategy: z.array(z.string()),
  recovered_symbol_count: z.number().int().nonnegative(),
  recovered_symbol_preview: z.array(
    z.object({
      address: z.string(),
      recovered_name: z.string(),
      name_strategy: z.string(),
      confidence: z.number(),
    })
  ),
  components: z.object({
    runtime_detect: z.object({
      ok: z.boolean(),
      warning_count: z.number().int().nonnegative(),
      error_count: z.number().int().nonnegative(),
    }),
    strings_extract: z.object({
      ok: z.boolean(),
      warning_count: z.number().int().nonnegative(),
      error_count: z.number().int().nonnegative(),
    }),
    smart_recover: z.object({
      ok: z.boolean(),
      warning_count: z.number().int().nonnegative(),
      error_count: z.number().int().nonnegative(),
    }),
    symbols_recover: z.object({
      ok: z.boolean(),
      warning_count: z.number().int().nonnegative(),
      error_count: z.number().int().nonnegative(),
    }),
    binary_role_profile: z.object({
      ok: z.boolean(),
      warning_count: z.number().int().nonnegative(),
      error_count: z.number().int().nonnegative(),
    }),
  }),
  importable_with_code_functions_define: z.boolean(),
  evidence: z.array(z.string()),
  analysis_priorities: z.array(z.string()),
  next_steps: z.array(z.string()),
})

export const rustBinaryAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: RustBinaryAnalyzeDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const rustBinaryAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze Rust-oriented PE binaries by correlating runtime hints, crate/toolchain strings, smart function recovery, and recovered symbol names.',
  inputSchema: rustBinaryAnalyzeInputSchema,
  outputSchema: rustBinaryAnalyzeOutputSchema,
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

type SmartRecoverData = {
  strategy?: string[]
  count?: number
}

type SymbolsRecoverData = {
  primary_runtime?: string | null
  runtime_hints?: string[]
  crate_hints?: string[]
  count?: number
  symbols?: Array<{
    address: string
    recovered_name: string
    name_strategy: string
    confidence: number
  }>
}

interface RustBinaryAnalyzeDependencies {
  runtimeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  stringsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  smartRecoverHandler?: (args: ToolArgs) => Promise<WorkerResult>
  symbolsRecoverHandler?: (args: ToolArgs) => Promise<WorkerResult>
  binaryRoleHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  const seen = new Set<string>()
  const output: string[] = []
  for (const value of values) {
    const normalized = (value || '').trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    output.push(normalized)
  }
  return output
}

function clamp(value: number, min = 0, max = 1): number {
  if (!Number.isFinite(value)) {
    return min
  }
  return Math.min(max, Math.max(min, value))
}

function extractCrateNameFromCargoPath(input: string): string | null {
  const normalized = input.replace(/\//g, '\\')
  const match = normalized.match(
    /cargo\\(?:registry\\src|git\\checkouts)\\[^\\]+\\([^\\]+)(?:\\|$)/i
  )
  if (!match?.[1]) {
    return null
  }
  return match[1].replace(/-\d[\w.+-]*$/, '').toLowerCase()
}

function detectLibraryHints(str: string): string[] {
  return LIBRARY_HINT_PATTERNS.filter((hint) => hint.patterns.some((pattern) => pattern.test(str))).map(
    (hint) => hint.name
  )
}

function analyzeRustStrings(strings: unknown[]): {
  cargoPaths: string[]
  rustMarkers: string[]
  asyncRuntimeMarkers: string[]
  panicMarkers: string[]
  crateNames: string[]
  libraryHints: string[]
} {
  const cargoPaths: string[] = []
  const rustMarkers: string[] = []
  const asyncRuntimeMarkers: string[] = []
  const panicMarkers: string[] = []
  const crateNames: string[] = []
  const libraryHints: string[] = []

  for (const rawEntry of strings) {
    const str =
      typeof rawEntry === 'string'
        ? rawEntry
        : rawEntry && typeof rawEntry === 'object' && 'string' in rawEntry
          ? String((rawEntry as { string?: unknown }).string || '')
          : ''
    if (!str) {
      continue
    }

    const cargoMatch = str.match(/cargo[\\/](?:registry[\\/]src|git[\\/]checkouts)[^\r\n]*/i)
    if (cargoMatch?.[0]) {
      cargoPaths.push(cargoMatch[0])
      const crateName = extractCrateNameFromCargoPath(cargoMatch[0])
      if (crateName) {
        crateNames.push(crateName)
      }
    }

    if (/rust_panic|core::panicking|panic_unwind|alloc::|std::rt|rustc|\\src\\main\.rs|\\src\\lib\.rs/i.test(str)) {
      rustMarkers.push(str)
    }
    if (/tokio|async|futures|mio|spawn_blocking|joinhandle|reactor/i.test(str)) {
      asyncRuntimeMarkers.push(str)
    }
    if (/panic|panicking|assertion failed|unwrap failed|expect failed/i.test(str)) {
      panicMarkers.push(str)
    }

    libraryHints.push(...detectLibraryHints(str))
  }

  return {
    cargoPaths: uniqueStrings(cargoPaths),
    rustMarkers: uniqueStrings(rustMarkers),
    asyncRuntimeMarkers: uniqueStrings(asyncRuntimeMarkers),
    panicMarkers: uniqueStrings(panicMarkers),
    crateNames: uniqueStrings(crateNames),
    libraryHints: uniqueStrings(libraryHints),
  }
}

function buildRustConfidence(options: {
  runtimeHints: string[]
  cargoPaths: string[]
  rustMarkers: string[]
  crateHints: string[]
  recoveredFunctionCount: number
  recoveredSymbolCount: number
}): number {
  let score = 0.08
  if (options.runtimeHints.some((item) => item.toLowerCase().includes('rust'))) score += 0.28
  if (options.cargoPaths.length > 0) score += 0.2
  if (options.rustMarkers.length > 0) score += 0.17
  if (options.crateHints.length > 0) score += 0.15
  if (options.recoveredFunctionCount > 0) score += 0.06
  if (options.recoveredSymbolCount > 0) score += 0.06
  return clamp(score)
}

export function createRustBinaryAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: RustBinaryAnalyzeDependencies = {}
) {
  const runtimeHandler =
    dependencies.runtimeHandler || createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const stringsHandler =
    dependencies.stringsHandler || createStringsExtractHandler(workspaceManager, database, cacheManager)
  const smartRecoverHandler =
    dependencies.smartRecoverHandler ||
    createCodeFunctionsSmartRecoverHandler(workspaceManager, database, cacheManager)
  const symbolsRecoverHandler =
    dependencies.symbolsRecoverHandler ||
    createPESymbolsRecoverHandler(workspaceManager, database, cacheManager)
  const binaryRoleHandler =
    dependencies.binaryRoleHandler ||
    createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = rustBinaryAnalyzeInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          max_strings: input.max_strings,
          max_symbol_preview: input.max_symbol_preview,
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

      const [runtimeResult, stringsResult, smartRecoverResult, symbolsRecoverResult, binaryRoleResult] =
        await Promise.all([
          runtimeHandler({ sample_id: input.sample_id, force_refresh: input.force_refresh }),
          stringsHandler({
            sample_id: input.sample_id,
            category_filter: 'all',
            max_strings: input.max_strings,
            force_refresh: input.force_refresh,
          }),
          smartRecoverHandler({ sample_id: input.sample_id, force_refresh: input.force_refresh }),
          symbolsRecoverHandler({
            sample_id: input.sample_id,
            max_string_hints: input.max_strings,
            force_refresh: input.force_refresh,
          }),
          binaryRoleHandler({ sample_id: input.sample_id, max_strings: input.max_strings, force_refresh: input.force_refresh }),
        ])

      const componentStatus = {
        runtime_detect: {
          ok: runtimeResult.ok,
          warning_count: runtimeResult.warnings?.length || 0,
          error_count: runtimeResult.errors?.length || 0,
        },
        strings_extract: {
          ok: stringsResult.ok,
          warning_count: stringsResult.warnings?.length || 0,
          error_count: stringsResult.errors?.length || 0,
        },
        smart_recover: {
          ok: smartRecoverResult.ok,
          warning_count: smartRecoverResult.warnings?.length || 0,
          error_count: smartRecoverResult.errors?.length || 0,
        },
        symbols_recover: {
          ok: symbolsRecoverResult.ok,
          warning_count: symbolsRecoverResult.warnings?.length || 0,
          error_count: symbolsRecoverResult.errors?.length || 0,
        },
        binary_role_profile: {
          ok: binaryRoleResult.ok,
          warning_count: binaryRoleResult.warnings?.length || 0,
          error_count: binaryRoleResult.errors?.length || 0,
        },
      }

      const warnings = [
        ...(runtimeResult.warnings || []).map((item) => `runtime: ${item}`),
        ...(runtimeResult.ok ? [] : (runtimeResult.errors || []).map((item) => `runtime error: ${item}`)),
        ...(stringsResult.warnings || []).map((item) => `strings: ${item}`),
        ...(stringsResult.ok ? [] : (stringsResult.errors || []).map((item) => `strings error: ${item}`)),
        ...(smartRecoverResult.warnings || []).map((item) => `smart_recover: ${item}`),
        ...(smartRecoverResult.ok
          ? []
          : (smartRecoverResult.errors || []).map((item) => `smart_recover error: ${item}`)),
        ...(symbolsRecoverResult.warnings || []).map((item) => `symbols_recover: ${item}`),
        ...(symbolsRecoverResult.ok
          ? []
          : (symbolsRecoverResult.errors || []).map((item) => `symbols_recover error: ${item}`)),
        ...(binaryRoleResult.warnings || []).map((item) => `binary_role: ${item}`),
        ...(binaryRoleResult.ok
          ? []
          : (binaryRoleResult.errors || []).map((item) => `binary_role error: ${item}`)),
      ]

      const runtimeData = (runtimeResult.ok ? runtimeResult.data : undefined) as RuntimeDetectData | undefined
      const stringsData = (stringsResult.ok ? stringsResult.data : undefined) as StringsData | undefined
      const smartRecoverData = (smartRecoverResult.ok ? smartRecoverResult.data : undefined) as SmartRecoverData | undefined
      const symbolsData = (symbolsRecoverResult.ok ? symbolsRecoverResult.data : undefined) as SymbolsRecoverData | undefined
      const binaryProfile = binaryRoleResult.ok ? (binaryRoleResult.data as z.infer<typeof BinaryRoleProfileDataSchema>) : undefined

      const rawStrings = stringsData?.strings || []
      const stringAnalysis = analyzeRustStrings(rawStrings)

      const libraryProfile = buildLibraryProfile(
        {
          cargoPaths: stringAnalysis.cargoPaths,
          crateNames: stringAnalysis.crateNames,
          libraryHints: stringAnalysis.libraryHints,
          rustMarkers: stringAnalysis.rustMarkers,
        },
        runtimeData || {}
      )

      const runtimeHints = uniqueStrings([
        ...(runtimeData?.suspected || []).map((item) => item.runtime),
        ...(symbolsData?.runtime_hints || []),
        ...(libraryProfile?.ecosystems || []),
      ])
      const crateHints = uniqueStrings([
        ...(symbolsData?.crate_hints || []),
        ...stringAnalysis.crateNames,
        ...(libraryProfile?.top_crates || []),
      ])

      const recoveredFunctionCount = smartRecoverData?.count || 0
      const recoveredFunctionStrategy = smartRecoverData?.strategy || []
      const recoveredSymbolCount = symbolsData?.count || 0
      const recoveredSymbolPreview = (symbolsData?.symbols || []).slice(0, input.max_symbol_preview)

      const confidence = buildRustConfidence({
        runtimeHints,
        cargoPaths: stringAnalysis.cargoPaths,
        rustMarkers: stringAnalysis.rustMarkers,
        crateHints,
        recoveredFunctionCount,
        recoveredSymbolCount,
      })
      const suspectedRust = confidence >= 0.42

      const evidence = uniqueStrings([
        ...(runtimeData?.suspected || [])
          .filter((item) => item.runtime.toLowerCase().includes('rust'))
          .flatMap((item) => item.evidence || []),
        ...stringAnalysis.cargoPaths.slice(0, 3).map((item) => `Cargo path: ${item}`),
        ...stringAnalysis.rustMarkers.slice(0, 3).map((item) => `Rust marker: ${item}`),
        ...stringAnalysis.asyncRuntimeMarkers.slice(0, 2).map((item) => `Async/runtime marker: ${item}`),
        ...stringAnalysis.panicMarkers.slice(0, 2).map((item) => `Panic marker: ${item}`),
        ...((libraryProfile?.evidence || []).slice(0, 3)),
        ...(recoveredSymbolPreview.slice(0, 3).map((item) => `Recovered symbol: ${item.recovered_name}`)),
      ])

      const analysisPriorities = uniqueStrings([
        ...(binaryProfile?.analysis_priorities || []),
        recoveredFunctionCount > 0 ? 'feed_recovered_boundaries_into_code.functions.define' : '',
        recoveredSymbolCount > 0 ? 'review_recovered_symbol_names_before_manual_validation' : '',
        stringAnalysis.asyncRuntimeMarkers.length > 0 ? 'trace_async_runtime_and_scheduler_paths' : '',
        stringAnalysis.panicMarkers.length > 0 ? 'separate_panic_paths_from_primary_business_logic' : '',
        crateHints.includes('tokio') || crateHints.includes('mio')
          ? 'trace_runtime_bootstrap_and_async_task_dispatch'
          : '',
        crateHints.includes('goblin') || crateHints.includes('iced-x86')
          ? 'review_binary_parsing_and_disassembly_modules_first'
          : '',
      ]).filter(Boolean)

      const nextSteps = uniqueStrings([
        recoveredFunctionCount > 0
          ? 'Use code.functions.define with source=smart_recover or symbols_recover to materialize the recovered function index.'
          : 'Use pe.pdata.extract to inspect the PE exception directory directly if function recovery remains empty.',
        'Run ghidra.analyze with options.language_id / options.cspec / options.script_paths when Rust auto-detection under-identifies functions.',
        recoveredSymbolCount > 0
          ? 'Use code.functions.define with recovered_name values to preserve recovered symbol names before reconstruct/export.'
          : 'Run pe.symbols.recover after strings extraction to derive more descriptive recovered names.',
      ])

      const payload = {
        sample_id: input.sample_id,
        suspected_rust: suspectedRust,
        confidence,
        primary_runtime: symbolsData?.primary_runtime || runtimeHints[0] || null,
        runtime_hints: runtimeHints,
        cargo_paths: stringAnalysis.cargoPaths,
        rust_markers: stringAnalysis.rustMarkers,
        async_runtime_markers: stringAnalysis.asyncRuntimeMarkers,
        panic_markers: stringAnalysis.panicMarkers,
        crate_hints: crateHints,
        library_profile: libraryProfile,
        binary_profile: binaryProfile,
        recovered_function_count: recoveredFunctionCount,
        recovered_function_strategy: recoveredFunctionStrategy,
        recovered_symbol_count: recoveredSymbolCount,
        recovered_symbol_preview: recoveredSymbolPreview,
        components: componentStatus,
        importable_with_code_functions_define: recoveredFunctionCount > 0 || recoveredSymbolCount > 0,
        evidence,
        analysis_priorities: analysisPriorities,
        next_steps: nextSteps,
      }

      await cacheManager.setCachedResult(cacheKey, payload, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: payload,
        warnings: warnings.length > 0 ? warnings : undefined,
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
