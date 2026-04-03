import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { extractPdataFromPE } from '../../../pe-runtime-functions.js'
import { resolvePrimarySamplePath } from '../../../sample-workspace.js'

const TOOL_NAME = 'pe.pdata.extract'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const pePdataExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type PEPdataExtractInput = z.infer<typeof pePdataExtractInputSchema>

export const pePdataExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      machine: z.number(),
      machine_name: z.string(),
      image_base: z.number(),
      entry_point_rva: z.number(),
      exception_directory_rva: z.number(),
      exception_directory_size: z.number(),
      pdata_present: z.boolean(),
      xdata_present: z.boolean(),
      count: z.number(),
      sections: z.array(
        z.object({
          name: z.string(),
          virtual_address: z.number(),
          virtual_size: z.number(),
          raw_size: z.number(),
          raw_pointer: z.number(),
          characteristics: z.number(),
          executable: z.boolean(),
        })
      ),
      exports: z.array(
        z.object({
          rva: z.number(),
          name: z.string(),
          ordinal: z.number(),
          is_forwarder: z.boolean(),
        })
      ),
      entries: z.array(
        z.object({
          begin_rva: z.number(),
          end_rva: z.number(),
          size: z.number(),
          begin_va: z.number(),
          end_va: z.number(),
          begin_address: z.string(),
          end_address: z.string(),
          unwind_info_rva: z.number(),
          section_name: z.string().nullable(),
          executable_section: z.boolean(),
          confidence: z.number(),
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
            .nullable(),
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

export const pePdataExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Parse the PE exception directory / .pdata section and extract x64 RUNTIME_FUNCTION entries with unwind metadata.',
  inputSchema: pePdataExtractInputSchema,
  outputSchema: pePdataExtractOutputSchema,
}

export function createPEPdataExtractHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, cacheManager } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as PEPdataExtractInput
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
      const result = extractPdataFromPE(samplePath)
      const normalized = {
        machine: result.machine,
        machine_name: result.machineName,
        image_base: result.imageBase,
        entry_point_rva: result.entryPointRva,
        exception_directory_rva: result.exceptionDirectoryRva,
        exception_directory_size: result.exceptionDirectorySize,
        pdata_present: result.pdataPresent,
        xdata_present: result.xdataPresent,
        count: result.count,
        sections: result.sections.map((section) => ({
          name: section.name,
          virtual_address: section.virtualAddress,
          virtual_size: section.virtualSize,
          raw_size: section.rawSize,
          raw_pointer: section.rawPointer,
          characteristics: section.characteristics,
          executable: section.executable,
        })),
        exports: result.exports.map((record) => ({
          rva: record.rva,
          name: record.name,
          ordinal: record.ordinal,
          is_forwarder: record.isForwarder,
        })),
        entries: result.entries.map((entry) => ({
          begin_rva: entry.beginRva,
          end_rva: entry.endRva,
          size: entry.size,
          begin_va: entry.beginVa,
          end_va: entry.endVa,
          begin_address: entry.beginAddress,
          end_address: entry.endAddress,
          unwind_info_rva: entry.unwindInfoRva,
          section_name: entry.sectionName,
          executable_section: entry.executableSection,
          confidence: entry.confidence,
          unwind: entry.unwind
            ? {
                version: entry.unwind.version,
                flags: entry.unwind.flags,
                flag_names: entry.unwind.flagNames,
                prolog_size: entry.unwind.prologSize,
                unwind_code_count: entry.unwind.unwindCodeCount,
                frame_register: entry.unwind.frameRegister,
                frame_register_id: entry.unwind.frameRegisterId,
                frame_offset: entry.unwind.frameOffset,
                handler_rva: entry.unwind.handlerRva,
                chained_runtime_function: entry.unwind.chainedRuntimeFunction
                  ? {
                      begin_rva: entry.unwind.chainedRuntimeFunction.beginRva,
                      end_rva: entry.unwind.chainedRuntimeFunction.endRva,
                      unwind_info_rva: entry.unwind.chainedRuntimeFunction.unwindInfoRva,
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
