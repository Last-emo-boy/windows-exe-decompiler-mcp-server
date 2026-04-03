/**
 * unpack.auto tool implementation
 * Automatically unpacks a packed binary using the best available backend
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import {
  selectUnpackStrategy,
  executeUnpackBackend,
  registerChildSample,
  type PackerDetectionResult,
  type UnpackBackend,
} from '../unpack-strategy.js'

const TOOL_NAME = 'unpack.auto'
const MAX_UNPACK_LAYERS = 3

// ============================================================================
// Input/Output Schemas
// ============================================================================

export const UnpackAutoInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_layers: z
    .number()
    .int()
    .min(1)
    .max(MAX_UNPACK_LAYERS)
    .default(MAX_UNPACK_LAYERS)
    .describe('Maximum unpack iterations for multi-layer packed binaries (1-3)'),
  force_backend: z
    .enum(['upx_cli', 'speakeasy_dump', 'qiling_oep_dump'])
    .optional()
    .describe('Force a specific unpack backend instead of auto-selection'),
})

export type UnpackAutoInput = z.infer<typeof UnpackAutoInputSchema>

export const UnpackAutoOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      original_sample_id: z.string(),
      unpacked_sample_id: z.string().nullable(),
      layers_unpacked: z.number(),
      layer_details: z.array(
        z.object({
          layer: z.number(),
          backend: z.string(),
          packer_name: z.string(),
          input_sample_id: z.string(),
          output_sample_id: z.string().nullable(),
          success: z.boolean(),
          error: z.string().nullable(),
        })
      ),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
})

// ============================================================================
// Tool Definition
// ============================================================================

export const unpackAutoToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Automatically unpack a packed binary using the best available backend (UPX, Speakeasy memory dump, or Qiling OEP dump). ' +
    'Reads packer detection results from prior analysis, selects the optimal unpack strategy, executes it, ' +
    'and registers the unpacked binary as a child sample. Supports multi-layer unpacking up to 3 iterations.',
  inputSchema: UnpackAutoInputSchema,
  outputSchema: UnpackAutoOutputSchema,
}

// ============================================================================
// Tool Handler
// ============================================================================

function extractPackerResult(database: DatabaseManager, sampleId: string): PackerDetectionResult {
  // Try to read packer detection from analysis_evidence
  const sample = database.findSample(sampleId)
  if (!sample) {
    return { packed: false, confidence: 0, packer_names: [] }
  }

  // Look for packer.detect artifact data
  const artifacts = database.findArtifactsByType(sampleId, 'packer_detect')
  if (artifacts.length > 0) {
    // Evidence already persisted
  }

  // Try analysis_evidence table for packer detection results
  try {
    const evidenceRows = database.findAnalysisEvidenceBySample(sampleId, 'packer_detect')
    if (evidenceRows.length > 0) {
      const latest = evidenceRows[0]
      const result =
        typeof latest.result_json === 'string'
          ? JSON.parse(latest.result_json)
          : null
      if (result) {
        const packed = Boolean(result.packed)
        const confidence =
          typeof result.confidence === 'number' ? result.confidence : 0
        const detections = Array.isArray(result.detections) ? result.detections : []
        const packer_names = detections
          .map((d: { name?: string }) => String(d.name || ''))
          .filter(Boolean)
        return { packed, confidence, packer_names }
      }
    }
  } catch {
    // Fallback: try canonical evidence
  }

  // Try fast_profile stage result
  const runs = database.findAnalysisRunsBySample(sampleId)
  if (runs.length > 0) {
    const latestRun = runs[0]
    const stage = database.findAnalysisRunStage(latestRun.id, 'fast_profile')
    if (stage?.result_json) {
      try {
        const result = JSON.parse(stage.result_json)
        const packerData = result?.raw_results?.packer
        if (packerData) {
          return {
            packed: Boolean(packerData.packed),
            confidence:
              typeof packerData.confidence === 'number'
                ? packerData.confidence
                : 0,
            packer_names: Array.isArray(packerData.detections)
              ? packerData.detections
                  .map((d: { name?: string }) => String(d.name || ''))
                  .filter(Boolean)
              : [],
            high_entropy: Boolean(packerData.evidence?.high_entropy),
          }
        }
        // Check packed_state from the profile envelope
        if (result?.packed_state === 'confirmed_packed' || result?.packed_state === 'suspected_packed') {
          return {
            packed: true,
            confidence: result?.unpack_confidence || 0.5,
            packer_names: [],
            high_entropy: true,
          }
        }
      } catch {
        // ignore parse errors
      }
    }
  }

  return { packed: false, confidence: 0, packer_names: [] }
}

export function createUnpackAutoHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = UnpackAutoInputSchema.parse(args)

      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const layerDetails: Array<{
        layer: number
        backend: string
        packer_name: string
        input_sample_id: string
        output_sample_id: string | null
        success: boolean
        error: string | null
      }> = []

      let currentSampleId = input.sample_id
      let finalUnpackedId: string | null = null
      const warnings: string[] = []

      for (let layer = 1; layer <= input.max_layers; layer++) {
        // Get packer detection for current layer
        const packerResult = extractPackerResult(database, currentSampleId)

        if (!packerResult.packed && layer > 1) {
          // No more packing detected — done
          break
        }

        if (!packerResult.packed && layer === 1) {
          return {
            ok: true,
            data: {
              original_sample_id: input.sample_id,
              unpacked_sample_id: null,
              layers_unpacked: 0,
              layer_details: [],
              recommended_next_tools: ['workflow.analyze.start', 'workflow.analyze.promote'],
              next_actions: ['No packing detected — proceed with standard analysis.'],
            },
            warnings: ['No packing detected for this sample.'],
          }
        }

        // Select strategy
        let strategy = input.force_backend
          ? {
              backend: input.force_backend as UnpackBackend,
              packer_name: 'forced',
              confidence: packerResult.confidence,
              description: `Forced backend: ${input.force_backend}`,
            }
          : selectUnpackStrategy(packerResult)

        if (!strategy) {
          warnings.push(
            `Layer ${layer}: No suitable unpack strategy found for confidence=${packerResult.confidence}`
          )
          layerDetails.push({
            layer,
            backend: 'none',
            packer_name: packerResult.packer_names[0] || 'unknown',
            input_sample_id: currentSampleId,
            output_sample_id: null,
            success: false,
            error: 'No suitable unpack strategy',
          })
          break
        }

        // Resolve sample path
        let samplePath: string
        try {
          const resolved = await resolvePrimarySamplePath(workspaceManager, currentSampleId)
          samplePath = resolved.samplePath
        } catch {
          layerDetails.push({
            layer,
            backend: strategy.backend,
            packer_name: strategy.packer_name,
            input_sample_id: currentSampleId,
            output_sample_id: null,
            success: false,
            error: 'Sample file not found in workspace',
          })
          break
        }

        // Execute unpack
        const result = await executeUnpackBackend(strategy.backend, samplePath)

        if (!result.ok || !result.unpacked_path) {
          layerDetails.push({
            layer,
            backend: strategy.backend,
            packer_name: strategy.packer_name,
            input_sample_id: currentSampleId,
            output_sample_id: null,
            success: false,
            error: result.error || 'Unpack failed',
          })
          warnings.push(`Layer ${layer}: ${result.error || 'Unpack failed'}`)
          break
        }

        // Register child sample
        try {
          const child = await registerChildSample(
            workspaceManager,
            database,
            currentSampleId,
            result.unpacked_path,
            {
              backend: strategy.backend,
              packer_name: strategy.packer_name,
              layer,
            }
          )

          layerDetails.push({
            layer,
            backend: strategy.backend,
            packer_name: strategy.packer_name,
            input_sample_id: currentSampleId,
            output_sample_id: child.sample_id,
            success: true,
            error: null,
          })

          finalUnpackedId = child.sample_id
          currentSampleId = child.sample_id
        } catch (regError) {
          layerDetails.push({
            layer,
            backend: strategy.backend,
            packer_name: strategy.packer_name,
            input_sample_id: currentSampleId,
            output_sample_id: null,
            success: false,
            error: `Child registration failed: ${regError instanceof Error ? regError.message : String(regError)}`,
          })
          break
        }
      }

      const layersUnpacked = layerDetails.filter((l) => l.success).length

      return {
        ok: layersUnpacked > 0,
        data: {
          original_sample_id: input.sample_id,
          unpacked_sample_id: finalUnpackedId,
          layers_unpacked: layersUnpacked,
          layer_details: layerDetails,
          recommended_next_tools: finalUnpackedId
            ? [
                'workflow.analyze.start',
                'pe.fingerprint',
                'pe.imports.extract',
                'packer.detect',
              ]
            : ['workflow.analyze.promote', 'upx.inspect'],
          next_actions: finalUnpackedId
            ? [
                `Run workflow.analyze.start on the unpacked sample ${finalUnpackedId} for clean analysis.`,
                'Compare original vs unpacked with artifact reading tools.',
              ]
            : [
                'Try a different unpack backend with force_backend parameter.',
                'Use manual unpack tools like upx.inspect with operation=decompress.',
              ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: layersUnpacked === 0 && layerDetails.length > 0
          ? ['All unpack attempts failed']
          : undefined,
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
      }
    }
  }
}
