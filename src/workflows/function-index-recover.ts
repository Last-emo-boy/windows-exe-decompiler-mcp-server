import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createCodeFunctionsSmartRecoverHandler } from '../tools/code-functions-smart-recover.js'
import { createPESymbolsRecoverHandler } from '../plugins/pe-analysis/tools/pe-symbols-recover.js'
import { createCodeFunctionsDefineHandler } from '../tools/code-functions-define.js'
import { DecompilerWorker } from '../decompiler-worker.js'

const TOOL_NAME = 'workflow.function_index_recover'

export const FunctionIndexRecoverWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  define_from: z
    .enum(['auto', 'smart_recover', 'symbols_recover'])
    .default('auto')
    .describe('Which recovered source should be materialized into the function index'),
  max_string_hints: z
    .number()
    .int()
    .min(20)
    .max(400)
    .default(120)
    .describe('Maximum strings inspected when pe.symbols.recover derives recovered names'),
  replace_all: z
    .boolean()
    .default(true)
    .describe('Replace the existing function index before importing recovered boundaries'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the materialized function-definition artifact'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed function_definition analysis row for the imported index'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting recovered function-definition artifacts'),
  include_rank_preview: z
    .boolean()
    .default(true)
    .describe('Return a ranked preview after the recovered function index has been materialized'),
  rank_topk: z
    .number()
    .int()
    .min(1)
    .max(40)
    .default(12)
    .describe('Number of ranked functions returned when include_rank_preview=true'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache in smart_recover and symbols_recover'),
})

const RankPreviewSchema = z.object({
  address: z.string(),
  name: z.string().nullable().optional(),
  score: z.number().nullable().optional(),
  tags: z.array(z.string()).optional(),
  summary: z.string().nullable().optional(),
})

export const FunctionIndexRecoverWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      define_from: z.enum(['smart_recover', 'symbols_recover']),
      recovered_function_count: z.number().int().nonnegative(),
      recovered_symbol_count: z.number().int().nonnegative(),
      imported_count: z.number().int().nonnegative(),
      function_index_status: z.enum(['ready']),
      decompile_status: z.enum(['missing']),
      cfg_status: z.enum(['missing']),
      recovery_strategy: z.array(z.string()),
      imported_artifact: z
        .object({
          id: z.string(),
          type: z.string(),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
        })
        .optional(),
      analysis_id: z.string().optional(),
      imported_function_preview: z.array(
        z.object({
          address: z.string(),
          rva: z.number().nullable(),
          size: z.number().nullable(),
          name: z.string(),
          is_entry_point: z.boolean(),
          is_exported: z.boolean(),
        })
      ),
      recovered_symbol_preview: z.array(
        z.object({
          address: z.string(),
          recovered_name: z.string(),
          name_strategy: z.string(),
          confidence: z.number(),
        })
      ),
      rank_preview: z.array(RankPreviewSchema).optional(),
      next_steps: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const functionIndexRecoverWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover a non-Ghidra function index by chaining code.functions.smart_recover, pe.symbols.recover, and code.functions.define, then optionally return a ranked preview.',
  inputSchema: FunctionIndexRecoverWorkflowInputSchema,
  outputSchema: FunctionIndexRecoverWorkflowOutputSchema,
}

type SmartRecoverData = {
  strategy: string[]
  count: number
  functions: Array<{
    address: string
    rva: number
    size: number
    name: string
    is_entry_point: boolean
    is_exported: boolean
    export_name?: string
    evidence: string[]
  }>
}

type SymbolsRecoverData = {
  count: number
  symbols: Array<{
    address: string
    rva: number
    size: number
    recovered_name: string
    confidence: number
    name_strategy: string
    evidence: string[]
    is_entry_point: boolean
    is_exported: boolean
    export_name?: string
  }>
}

type DefineData = {
  imported_count: number
  function_index_status: 'ready'
  decompile_status: 'missing'
  cfg_status: 'missing'
  imported_functions: Array<{
    address: string
    rva: number | null
    size: number | null
    name: string
    is_entry_point: boolean
    is_exported: boolean
  }>
  analysis_id?: string
  artifact?: {
    id: string
    type: string
    path: string
    sha256: string
    mime?: string
  }
  next_steps: string[]
}

interface FunctionIndexRecoverWorkflowDependencies {
  smartRecoverHandler?: (args: ToolArgs) => Promise<WorkerResult>
  symbolsRecoverHandler?: (args: ToolArgs) => Promise<WorkerResult>
  defineHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function normalizeRankPreview(items: any[]): Array<z.infer<typeof RankPreviewSchema>> {
  return items.map((item) => ({
    address: String(item.address),
    name: item.name ? String(item.name) : null,
    score: typeof item.score === 'number' ? item.score : null,
    tags: Array.isArray(item.tags)
      ? item.tags.map((entry: unknown) => String(entry))
      : undefined,
    summary: item.summary ? String(item.summary) : null,
  }))
}

export function createFunctionIndexRecoverWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies: FunctionIndexRecoverWorkflowDependencies = {}
) {
  const smartRecoverHandler =
    dependencies.smartRecoverHandler ||
    createCodeFunctionsSmartRecoverHandler(workspaceManager, database, cacheManager)
  const symbolsRecoverHandler =
    dependencies.symbolsRecoverHandler ||
    createPESymbolsRecoverHandler({ workspaceManager, database, cacheManager } as any)
  const defineHandler =
    dependencies.defineHandler || createCodeFunctionsDefineHandler(workspaceManager, database)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = FunctionIndexRecoverWorkflowInputSchema.parse(args)
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

      const warnings: string[] = []
      const [smartRecoverResult, symbolsRecoverResult] = await Promise.all([
        smartRecoverHandler({
          sample_id: input.sample_id,
          force_refresh: input.force_refresh,
        }),
        symbolsRecoverHandler({
          sample_id: input.sample_id,
          max_string_hints: input.max_string_hints,
          force_refresh: input.force_refresh,
        }),
      ])

      if (!smartRecoverResult.ok || !smartRecoverResult.data) {
        return {
          ok: false,
          errors: [
            `code.functions.smart_recover failed: ${(smartRecoverResult.errors || ['unknown error']).join('; ')}`,
          ],
          warnings: [
            ...(smartRecoverResult.warnings || []),
            ...(symbolsRecoverResult.warnings || []),
          ],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const smartRecoverData = smartRecoverResult.data as SmartRecoverData
      const symbolsRecoverData =
        symbolsRecoverResult.ok && symbolsRecoverResult.data
          ? (symbolsRecoverResult.data as SymbolsRecoverData)
          : undefined

      if (!symbolsRecoverResult.ok) {
        warnings.push(
          `pe.symbols.recover unavailable: ${(symbolsRecoverResult.errors || ['unknown error']).join('; ')}`
        )
      }
      warnings.push(...(smartRecoverResult.warnings || []))
      warnings.push(...(symbolsRecoverResult.warnings || []))

      const symbolByAddress = new Map(
        (symbolsRecoverData?.symbols || []).map((item) => [item.address.toLowerCase(), item])
      )
      const symbolByRva = new Map(
        (symbolsRecoverData?.symbols || []).map((item) => [item.rva, item])
      )

      const defineFrom =
        input.define_from === 'auto'
          ? symbolsRecoverData && symbolsRecoverData.count > 0
            ? 'symbols_recover'
            : 'smart_recover'
          : input.define_from

      const definitions = smartRecoverData.functions.map((item) => {
        const symbol =
          symbolByAddress.get(item.address.toLowerCase()) ||
          symbolByRva.get(item.rva)
        const useRecoveredName = defineFrom === 'symbols_recover' && symbol
        return {
          address: item.address,
          rva: item.rva,
          size: item.size,
          name: useRecoveredName ? symbol.recovered_name : item.name,
          recovered_name: symbol?.recovered_name,
          is_entry_point: item.is_entry_point,
          is_exported: item.is_exported,
          evidence: Array.from(new Set([...(item.evidence || []), ...(symbol?.evidence || [])])),
          tags: Array.from(
            new Set([
              `recovery:${item.name}`,
              ...(symbol ? [`symbol_strategy:${symbol.name_strategy}`] : []),
              useRecoveredName ? 'name_source:recovered_symbol' : 'name_source:smart_recover',
            ])
          ),
        }
      })

      const defineResult = await defineHandler({
        sample_id: input.sample_id,
        definitions,
        source: defineFrom,
        replace_all: input.replace_all,
        persist_artifact: input.persist_artifact,
        register_analysis: input.register_analysis,
        session_tag: input.session_tag,
      })

      if (!defineResult.ok || !defineResult.data) {
        return {
          ok: false,
          errors: [
            `code.functions.define failed: ${(defineResult.errors || ['unknown error']).join('; ')}`,
          ],
          warnings: warnings.length > 0 ? warnings : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const defineData = defineResult.data as DefineData
      let rankPreview: Array<z.infer<typeof RankPreviewSchema>> | undefined
      if (input.include_rank_preview) {
        const decompilerWorker = new DecompilerWorker(database, workspaceManager)
        const ranked = await decompilerWorker.rankFunctions(input.sample_id, input.rank_topk)
        rankPreview = normalizeRankPreview(ranked)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          define_from: defineFrom,
          recovered_function_count: smartRecoverData.count,
          recovered_symbol_count: symbolsRecoverData?.count || 0,
          imported_count: defineData.imported_count,
          function_index_status: defineData.function_index_status,
          decompile_status: defineData.decompile_status,
          cfg_status: defineData.cfg_status,
          recovery_strategy: smartRecoverData.strategy,
          imported_artifact: defineData.artifact,
          analysis_id: defineData.analysis_id,
          imported_function_preview: defineData.imported_functions.slice(0, input.rank_topk),
          recovered_symbol_preview: (symbolsRecoverData?.symbols || [])
            .slice(0, input.rank_topk)
            .map((item) => ({
              address: item.address,
              recovered_name: item.recovered_name,
              name_strategy: item.name_strategy,
              confidence: item.confidence,
            })),
          rank_preview: rankPreview,
          next_steps: Array.from(
            new Set([
              ...defineData.next_steps,
              'Use code.functions.list / code.functions.rank to inspect the recovered index.',
              'Use code.functions.reconstruct or workflow.reconstruct after Ghidra decompile/CFG readiness improves.',
            ])
          ),
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: defineResult.artifacts,
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
