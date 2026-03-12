import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager, Function as DbFunction } from '../database.js'
import { extractPdataFromPE } from '../pe-runtime-functions.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'

const TOOL_NAME = 'code.functions.define'

const FunctionDefinitionSchema = z
  .object({
    address: z.string().optional().describe('Absolute virtual address such as 0x140001000'),
    va: z.number().int().nonnegative().optional().describe('Absolute virtual address as a numeric value'),
    rva: z.number().int().nonnegative().optional().describe('Relative virtual address. Converted using the PE image base.'),
    size: z.number().int().positive().optional().describe('Function size in bytes when known'),
    name: z.string().min(1).max(256).optional().describe('Preferred function name'),
    recovered_name: z.string().min(1).max(256).optional().describe('Recovered name from pe.symbols.recover when name is not present'),
    summary: z.string().max(2000).optional().describe('Optional analyst summary for this function'),
    tags: z.array(z.string()).optional().default([]).describe('Optional semantic or provenance tags'),
    caller_count: z.number().int().nonnegative().optional().describe('Optional caller count estimate'),
    callee_count: z.number().int().nonnegative().optional().describe('Optional callee count estimate'),
    is_entry_point: z.boolean().optional().default(false).describe('Mark the function as an entry point'),
    is_exported: z.boolean().optional().default(false).describe('Mark the function as exported'),
    callees: z.array(z.string()).optional().default([]).describe('Optional list of known callees'),
    score: z.number().min(0).max(1).optional().describe('Optional precomputed ranking score'),
    evidence: z.array(z.string()).optional().default([]).describe('Optional evidence strings that explain why this boundary was defined'),
  })
  .refine((value) => Boolean(value.address?.trim()) || value.va !== undefined || value.rva !== undefined, {
    message: 'Each function definition must provide at least one of address, va, or rva.',
  })

export const codeFunctionsDefineInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  definitions: z
    .array(FunctionDefinitionSchema)
    .min(1)
    .describe('Function boundaries or recovered function records to import into the function index'),
  source: z
    .enum(['manual', 'pdata', 'symbols_recover', 'smart_recover', 'external'])
    .optional()
    .default('manual')
    .describe('Provenance label recorded in the analysis and artifact metadata'),
  replace_all: z
    .boolean()
    .optional()
    .default(false)
    .describe('When true, replace the existing function index for this sample before importing the new definitions'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the imported function definitions as a stable artifact in reports/function_definitions'),
  register_analysis: z
    .boolean()
    .optional()
    .default(true)
    .describe('Insert a completed analysis row describing the imported function index'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used in the persisted artifact name and analysis metadata'),
})

export const codeFunctionsDefineOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      source: z.string(),
      replace_all: z.boolean(),
      imported_count: z.number().int().nonnegative(),
      function_index_status: z.enum(['ready']),
      decompile_status: z.enum(['missing']),
      cfg_status: z.enum(['missing']),
      image_base: z.number().nullable(),
      imported_functions: z.array(
        z.object({
          address: z.string(),
          rva: z.number().nullable(),
          size: z.number().nullable(),
          name: z.string(),
          is_entry_point: z.boolean(),
          is_exported: z.boolean(),
        })
      ),
      analysis_id: z.string().optional(),
      artifact: z
        .object({
          id: z.string(),
          type: z.string(),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
        })
        .optional(),
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

export const codeFunctionsDefineToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Define or import function boundaries manually or from recovered metadata so code.functions.list/rank/reconstruct can use a non-Ghidra function index.',
  inputSchema: codeFunctionsDefineInputSchema,
  outputSchema: codeFunctionsDefineOutputSchema,
}

function normalizeHexAddress(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error('Function address cannot be empty.')
  }
  const hex = trimmed.toLowerCase().startsWith('0x') ? trimmed.slice(2) : trimmed
  if (!/^[0-9a-f]+$/i.test(hex)) {
    throw new Error(`Invalid function address: ${value}`)
  }
  return `0x${hex.toLowerCase()}`
}

function sanitizePathToken(value: string | undefined): string {
  const normalized = (value || '').trim().replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '')
  return normalized.slice(0, 48)
}

export function createCodeFunctionsDefineHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionsDefineInputSchema.parse(args)
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

      let imageBase: number | null = null
      if (input.definitions.some((item) => !item.address && item.va === undefined && item.rva !== undefined)) {
        const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
        imageBase = extractPdataFromPE(samplePath).imageBase
      }

      const warnings: string[] = []
      const imported: DbFunction[] = []
      const importedSummary: Array<{
        address: string
        rva: number | null
        size: number | null
        name: string
        is_entry_point: boolean
        is_exported: boolean
      }> = []

      for (const item of input.definitions) {
        const name = (item.name || item.recovered_name || '').trim()
        if (!name) {
          warnings.push(
            `Skipped function definition ${item.address || (item.va !== undefined ? `va:${item.va}` : `rva:${item.rva}`)} because no name or recovered_name was provided.`
          )
          continue
        }

        let va: number
        let rva: number | null = item.rva ?? null

        if (item.address) {
          const normalizedAddress = normalizeHexAddress(item.address)
          va = Number.parseInt(normalizedAddress.slice(2), 16)
        } else if (item.va !== undefined) {
          va = item.va
        } else if (item.rva !== undefined) {
          if (imageBase === null) {
            throw new Error('Unable to resolve RVA definitions because the PE image base could not be determined.')
          }
          va = imageBase + item.rva
        } else {
          throw new Error('Each function definition must provide address, va, or rva.')
        }

        if (rva === null && imageBase !== null && va >= imageBase) {
          rva = va - imageBase
        }

        const address = normalizeHexAddress(`0x${va.toString(16)}`)
        const tags = Array.from(
          new Set([`source:${input.source}`, ...(item.tags || []), ...(item.evidence?.map((e) => `evidence:${e}`) || [])])
        )

        const summary =
          item.summary ||
          `Function boundary imported via code.functions.define (source=${input.source}${rva !== null ? `, rva=0x${rva.toString(16)}` : ''}).`

        imported.push({
          sample_id: input.sample_id,
          address,
          name,
          size: item.size ?? null,
          score: item.score ?? null,
          tags: tags.length > 0 ? JSON.stringify(tags) : null,
          summary,
          caller_count: item.caller_count ?? 0,
          callee_count: item.callee_count ?? 0,
          is_entry_point: item.is_entry_point ? 1 : 0,
          is_exported: item.is_exported ? 1 : 0,
          callees: (item.callees || []).length > 0 ? JSON.stringify(item.callees) : null,
        })

        importedSummary.push({
          address,
          rva,
          size: item.size ?? null,
          name,
          is_entry_point: Boolean(item.is_entry_point),
          is_exported: Boolean(item.is_exported),
        })
      }

      if (imported.length === 0) {
        return {
          ok: false,
          errors: ['No function definitions were imported after validation.'],
          warnings: warnings.length > 0 ? warnings : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      if (input.replace_all) {
        database.getDatabase().prepare('DELETE FROM functions WHERE sample_id = ?').run(input.sample_id)
      }
      database.insertFunctionsBatch(imported)

      let artifact: ArtifactRef | undefined
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        const workspace = await workspaceManager.createWorkspace(input.sample_id)
        const reportDir = path.join(workspace.reports, 'function_definitions')
        await fs.mkdir(reportDir, { recursive: true })

        const sanitizedSessionTag = sanitizePathToken(input.session_tag)
        const suffix = sanitizedSessionTag ? `_${sanitizedSessionTag}` : ''
        const fileName = `defined_functions_${input.source}${suffix}_${Date.now()}.json`
        const absolutePath = path.join(reportDir, fileName)
        const payload = {
          schema_version: 1,
          sample_id: input.sample_id,
          source: input.source,
          replace_all: input.replace_all,
          created_at: new Date().toISOString(),
          image_base: imageBase,
          functions: importedSummary,
        }
        const serialized = JSON.stringify(payload, null, 2)
        await fs.writeFile(absolutePath, serialized, 'utf-8')

        const artifactId = randomUUID()
        const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
        artifact = {
          id: artifactId,
          type: 'function_definition',
          path: `reports/function_definitions/${fileName}`,
          sha256: artifactSha256,
          mime: 'application/json',
        }
        database.insertArtifact({
          id: artifactId,
          sample_id: input.sample_id,
          type: artifact.type,
          path: artifact.path,
          sha256: artifact.sha256,
          mime: artifact.mime || null,
          created_at: new Date().toISOString(),
        })
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'function_definition',
          backend: input.source,
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            function_count: imported.length,
            function_source: input.source,
            replace_all: input.replace_all,
            artifact_id: artifact?.id || null,
            readiness: {
              function_index: {
                available: true,
                status: 'ready',
                reason: 'Function index imported manually or from recovered metadata.',
              },
              decompile: {
                available: false,
                status: 'missing',
                reason: 'Manual function definitions do not establish Ghidra decompile readiness.',
              },
              cfg: {
                available: false,
                status: 'missing',
                reason: 'Manual function definitions do not establish Ghidra CFG readiness.',
              },
            },
          }),
          metrics_json: JSON.stringify({
            imported_count: imported.length,
          }),
        })
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          source: input.source,
          replace_all: input.replace_all,
          imported_count: imported.length,
          function_index_status: 'ready',
          decompile_status: 'missing',
          cfg_status: 'missing',
          image_base: imageBase,
          imported_functions: importedSummary,
          analysis_id: analysisId,
          artifact,
          next_steps: [
            'Run code.functions.list or code.functions.rank to inspect the imported function index.',
            'Run code.functions.reconstruct to obtain degraded semantic reconstruction from the new function index.',
            'Run ghidra.analyze later if you still need decompile or CFG readiness.',
          ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
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
