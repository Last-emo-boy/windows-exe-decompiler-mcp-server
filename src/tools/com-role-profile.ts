import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js'

const TOOL_NAME = 'com.role.profile'

export const ComRoleProfileInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_exports: z
    .number()
    .int()
    .min(1)
    .max(24)
    .default(12)
    .describe('Maximum class-factory and registration exports surfaced in the COM role profile'),
  max_strings: z
    .number()
    .int()
    .min(20)
    .max(400)
    .default(140)
    .describe('Maximum strings inspected for CLSID, ProgID, interface, and registration hints'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup and recompute the COM role profile from source evidence'),
})

export const ComRoleProfileDataSchema = z.object({
  sample_id: z.string(),
  original_filename: z.string().nullable(),
  binary_role: z.string(),
  likely_com_server: z.boolean(),
  com_confidence: z.number().min(0).max(1),
  class_factory_exports: z.array(z.string()),
  registration_exports: z.array(z.string()),
  clsid_strings: z.array(z.string()),
  progid_strings: z.array(z.string()),
  interface_hints: z.array(z.string()),
  registration_strings: z.array(z.string()),
  class_factory_surface: z.object({
    class_factory_exports: z.array(z.string()),
    activation_markers: z.array(z.string()),
    interface_hints: z.array(z.string()),
    confidence: z.number().min(0).max(1),
  }),
  activation_steps: z.array(z.string()),
  host_interaction_profile: BinaryRoleProfileDataSchema.shape.host_interaction_profile,
  activation_model: z.string(),
  analysis_priorities: z.array(z.string()),
})

export const ComRoleProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: ComRoleProfileDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const comRoleProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Profile COM-oriented PE samples, including class factory exports, CLSID/ProgID strings, registration hints, and likely activation flow.',
  inputSchema: ComRoleProfileInputSchema,
  outputSchema: ComRoleProfileOutputSchema,
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
}

function inferActivationModel(profile: z.infer<typeof BinaryRoleProfileDataSchema>): string {
  if (profile.com_profile.class_factory_exports.length > 0) {
    return 'inproc_class_factory'
  }
  if (profile.com_profile.registration_strings.some((item) => /localserver32/i.test(item))) {
    return 'local_server_registration'
  }
  if (profile.com_profile.clsid_strings.length > 0 || profile.com_profile.progid_strings.length > 0) {
    return 'registration_strings_only'
  }
  return 'not_com_like'
}

function buildActivationSteps(profile: z.infer<typeof BinaryRoleProfileDataSchema>): string[] {
  const steps: string[] = []
  if (profile.export_dispatch_profile.registration_exports.length > 0) {
    steps.push('Review COM registration exports and registry-facing installation routines.')
  }
  if (profile.com_profile.registration_strings.some((item) => /inprocserver32/i.test(item))) {
    steps.push('Resolve the InprocServer32 registration path and associated CLSID/ProgID bindings.')
  }
  if (profile.com_profile.registration_strings.some((item) => /localserver32/i.test(item))) {
    steps.push('Check whether activation can fall back to a LocalServer32-style out-of-process server.')
  }
  if (profile.com_profile.class_factory_exports.length > 0) {
    steps.push('Trace DllGetClassObject or equivalent class-factory export into object instantiation logic.')
  }
  if (profile.com_profile.interface_hints.length > 0) {
    steps.push('Follow interface negotiation paths for IClassFactory/IUnknown/IDispatch-style flows.')
  }
  return dedupe(steps)
}

function buildClassFactorySurface(profile: z.infer<typeof BinaryRoleProfileDataSchema>) {
  const activationMarkers = dedupe(
    [
      ...profile.com_profile.clsid_strings,
      ...profile.com_profile.progid_strings,
      ...profile.com_profile.registration_strings.filter((item) => /inprocserver32|localserver32|appid|clsid/i.test(item)),
    ].slice(0, 8)
  )
  let confidence = profile.com_profile.class_factory_exports.length > 0 ? 0.64 : 0.28
  if (activationMarkers.length > 0) confidence += 0.16
  if (profile.com_profile.interface_hints.length > 0) confidence += 0.08
  return {
    class_factory_exports: profile.com_profile.class_factory_exports,
    activation_markers: activationMarkers,
    interface_hints: profile.com_profile.interface_hints,
    confidence: Math.min(1, confidence),
  }
}

export function createComRoleProfileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: {
    binaryRoleProfileHandler?: (args: ToolArgs) => Promise<WorkerResult>
  }
) {
  const binaryRoleProfileHandler =
    dependencies?.binaryRoleProfileHandler ||
    createBinaryRoleProfileHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = ComRoleProfileInputSchema.parse(args)
      const profileResult = await binaryRoleProfileHandler({
        sample_id: input.sample_id,
        max_exports: input.max_exports,
        max_strings: input.max_strings,
        force_refresh: input.force_refresh,
      })

      if (!profileResult.ok || !profileResult.data) {
        return {
          ok: false,
          errors: profileResult.errors || ['Failed to compute binary role profile'],
          warnings: profileResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const profile = BinaryRoleProfileDataSchema.parse(profileResult.data)
      const payload = {
        sample_id: profile.sample_id,
        original_filename: profile.original_filename,
        binary_role: profile.binary_role,
        likely_com_server: profile.indicators.com_server.likely,
        com_confidence: profile.com_profile.confidence,
        class_factory_exports: profile.com_profile.class_factory_exports,
        registration_exports: profile.export_dispatch_profile.registration_exports,
        clsid_strings: profile.com_profile.clsid_strings,
        progid_strings: profile.com_profile.progid_strings,
        interface_hints: profile.com_profile.interface_hints,
        registration_strings: profile.com_profile.registration_strings,
        class_factory_surface: buildClassFactorySurface(profile),
        activation_steps: buildActivationSteps(profile),
        host_interaction_profile: profile.host_interaction_profile,
        activation_model: inferActivationModel(profile),
        analysis_priorities: dedupe([
          ...profile.analysis_priorities,
          'trace_com_activation_and_class_factory_flow',
        ]),
      }

      return {
        ok: true,
        data: payload,
        warnings: profileResult.warnings,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
