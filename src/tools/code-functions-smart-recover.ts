import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { smartRecoverFunctionsFromPE } from '../pe-runtime-functions.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'

const TOOL_NAME = 'code.functions.smart_recover'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const codeFunctionsSmartRecoverInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export const codeFunctionsSmartRecoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      machine: z.number(),
      machine_name: z.string(),
      image_base: z.number(),
      entry_point_rva: z.number(),
      strategy: z.array(z.string()),
      count: z.number(),
      functions: z.array(
        z.object({
          address: z.string(),
          va: z.number(),
          rva: z.number(),
          size: z.number(),
          name: z.string(),
          name_source: z.enum(['entry_point', 'export', 'synthetic_sub']),
          confidence: z.number(),
          source: z.enum(['pdata_runtime_function', 'entry_point_only']),
          section_name: z.string().nullable(),
          executable_section: z.boolean(),
          is_entry_point: z.boolean(),
          is_exported: z.boolean(),
          export_name: z.string().optional(),
          evidence: z.array(z.string()),
          unwind: z
            .object({
              version: z.number(),
              flags: z.number(),
              flag_names: z.array(z.string()),
              prolog_size: z.number(),
              unwind_code_count: z.number(),
              frame_register: z.string().nullable(),
              frame_register_id: z.number(),
              frame_offset: z.number(),
              handler_rva: z.number().optional(),
              chained_runtime_function: z
                .object({
                  begin_rva: z.number(),
                  end_rva: z.number(),
                  unwind_info_rva: z.number(),
                })
                .optional(),
            })
            .nullable()
            .optional(),
        })
      ),
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

export const codeFunctionsSmartRecoverToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover function candidates heuristically from PE runtime metadata such as .pdata / exception directory, exports, and entry point.',
  inputSchema: codeFunctionsSmartRecoverInputSchema,
  outputSchema: codeFunctionsSmartRecoverOutputSchema,
}

export function createCodeFunctionsSmartRecoverHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as z.infer<typeof codeFunctionsSmartRecoverInputSchema>
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
        args: {},
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
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const result = smartRecoverFunctionsFromPE(samplePath)
      const normalized = {
        machine: result.machine,
        machine_name: result.machineName,
        image_base: result.imageBase,
        entry_point_rva: result.entryPointRva,
        strategy: result.strategy,
        count: result.count,
        functions: result.functions.map((item) => ({
          address: item.address,
          va: item.va,
          rva: item.rva,
          size: item.size,
          name: item.name,
          name_source: item.nameSource,
          confidence: item.confidence,
          source: item.source,
          section_name: item.sectionName,
          executable_section: item.executableSection,
          is_entry_point: item.isEntryPoint,
          is_exported: item.isExported,
          export_name: item.exportName,
          evidence: item.evidence,
          unwind: item.unwind
            ? {
                version: item.unwind.version,
                flags: item.unwind.flags,
                flag_names: item.unwind.flagNames,
                prolog_size: item.unwind.prologSize,
                unwind_code_count: item.unwind.unwindCodeCount,
                frame_register: item.unwind.frameRegister,
                frame_register_id: item.unwind.frameRegisterId,
                frame_offset: item.unwind.frameOffset,
                handler_rva: item.unwind.handlerRva,
                chained_runtime_function: item.unwind.chainedRuntimeFunction
                  ? {
                      begin_rva: item.unwind.chainedRuntimeFunction.beginRva,
                      end_rva: item.unwind.chainedRuntimeFunction.endRva,
                      unwind_info_rva: item.unwind.chainedRuntimeFunction.unwindInfoRva,
                    }
                  : undefined,
              }
            : null,
        })),
        warnings: result.warnings,
      }

      await cacheManager.setCachedResult(cacheKey, normalized, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: normalized,
        warnings: result.warnings.length > 0 ? result.warnings : undefined,
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
