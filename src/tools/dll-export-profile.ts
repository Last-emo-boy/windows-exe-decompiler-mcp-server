import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js'

const TOOL_NAME = 'dll.export.profile'

export const DllExportProfileInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_exports: z
    .number()
    .int()
    .min(1)
    .max(32)
    .default(16)
    .describe('Maximum exports and forwarders surfaced in the DLL export profile'),
  max_strings: z
    .number()
    .int()
    .min(20)
    .max(400)
    .default(120)
    .describe('Maximum strings inspected for COM/plugin/host heuristics'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup and recompute the DLL export profile from source evidence'),
})

export const DllExportProfileDataSchema = z.object({
  sample_id: z.string(),
  original_filename: z.string().nullable(),
  binary_role: z.string(),
  library_like: z.boolean(),
  role_confidence: z.number().min(0).max(1),
  export_surface: BinaryRoleProfileDataSchema.shape.export_surface,
  export_dispatch_profile: BinaryRoleProfileDataSchema.shape.export_dispatch_profile,
  host_interaction_profile: BinaryRoleProfileDataSchema.shape.host_interaction_profile,
  lifecycle_surface: z.object({
    lifecycle_exports: z.array(z.string()),
    lifecycle_imports: z.array(z.string()),
    attach_detach_strings: z.array(z.string()),
    confidence: z.number().min(0).max(1),
  }),
  class_factory_surface: z.object({
    class_factory_exports: z.array(z.string()),
    activation_markers: z.array(z.string()),
    confidence: z.number().min(0).max(1),
  }),
  callback_surface: z.object({
    callback_exports: z.array(z.string()),
    callback_strings: z.array(z.string()),
    host_hints: z.array(z.string()),
    confidence: z.number().min(0).max(1),
  }),
  dll_entry_hints: z.array(z.string()),
  likely_entry_model: z.string(),
  analysis_priorities: z.array(z.string()),
})

export const DllExportProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: DllExportProfileDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const dllExportProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Profile DLL-like export surfaces, dispatch models, DllMain lifecycle hints, and plugin/host callback patterns for PE samples.',
  inputSchema: DllExportProfileInputSchema,
  outputSchema: DllExportProfileOutputSchema,
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
}

function inferDllEntryModel(profile: z.infer<typeof BinaryRoleProfileDataSchema>): string {
  if (profile.com_profile.confidence >= 0.55 && profile.export_dispatch_profile.registration_exports.length > 0) {
    return 'registration_and_class_factory'
  }
  if (profile.host_interaction_profile.likely_hosted) {
    return 'hosted_plugin_or_callback_library'
  }
  if (profile.export_dispatch_profile.command_like_exports.length > 0) {
    return 'export_dispatch_library'
  }
  if (profile.export_surface.total_exports > 0) {
    return 'exported_library_surface'
  }
  return 'dll_lifecycle_only'
}

function collectDllEntryHints(profile: z.infer<typeof BinaryRoleProfileDataSchema>): string[] {
  const hints: string[] = []
  if (profile.export_dispatch_profile.registration_exports.length > 0) {
    hints.push('Registration exports suggest DllRegisterServer/DllInstall style lifecycle handling.')
  }
  if (profile.com_profile.class_factory_exports.length > 0) {
    hints.push('Class factory exports suggest DllGetClassObject / COM activation entry paths.')
  }
  if (profile.host_interaction_profile.callback_exports.length > 0) {
    hints.push('Callback-like exports suggest host-driven invocation rather than standalone execution.')
  }
  if (profile.host_interaction_profile.service_hooks.length > 0) {
    hints.push('Service-related hooks suggest SCM-facing lifecycle callbacks or service helper exports.')
  }
  if (profile.export_surface.forwarded_exports.length > 0) {
    hints.push('Forwarded exports suggest this DLL may act as a shim or adapter layer.')
  }
  if (profile.import_surface.process_related_imports.some((item) => /kernel32/i.test(item))) {
    hints.push('Kernel32 import surface suggests classic DllMain attach/detach side effects are worth reviewing.')
  }
  return dedupe(hints)
}

function buildLifecycleSurface(profile: z.infer<typeof BinaryRoleProfileDataSchema>) {
  const lifecycleExports = dedupe(
    profile.export_surface.notable_exports.filter((item) =>
      /dll(main|install|registerserver|unregisterserver)|attach|detach/i.test(item)
    )
  )
  const lifecycleImports = dedupe(
    profile.import_surface.process_related_imports.filter((item) => /kernel32|ntdll|psapi|dbghelp/i.test(item))
  )
  const attachDetachStrings = dedupe(
    [
      ...profile.host_interaction_profile.host_hints.filter((item) => /attach|detach|dll|module/i.test(item)),
      ...profile.export_surface.notable_exports.filter((item) => /attach|detach/i.test(item)),
    ].slice(0, 8)
  )
  let confidence = 0.18
  if (lifecycleImports.length > 0) confidence += 0.18
  if (lifecycleExports.length > 0) confidence += 0.22
  if (attachDetachStrings.length > 0) confidence += 0.14
  return {
    lifecycle_exports: lifecycleExports,
    lifecycle_imports: lifecycleImports,
    attach_detach_strings: attachDetachStrings,
    confidence: Math.min(1, confidence),
  }
}

function buildClassFactorySurface(profile: z.infer<typeof BinaryRoleProfileDataSchema>) {
  const activationMarkers = dedupe(
    [
      ...profile.com_profile.registration_strings.filter((item) => /inprocserver32|localserver32|appid|clsid/i.test(item)),
      ...profile.com_profile.interface_hints.filter((item) => /iclassfactory|iunknown|idispatch/i.test(item)),
      ...profile.com_profile.clsid_strings,
      ...profile.com_profile.progid_strings,
    ].slice(0, 8)
  )
  let confidence = profile.com_profile.class_factory_exports.length > 0 ? 0.58 : 0.24
  if (activationMarkers.length > 0) confidence += 0.18
  return {
    class_factory_exports: profile.com_profile.class_factory_exports,
    activation_markers: activationMarkers,
    confidence: Math.min(1, confidence),
  }
}

function buildCallbackSurface(profile: z.infer<typeof BinaryRoleProfileDataSchema>) {
  let confidence = profile.host_interaction_profile.callback_exports.length > 0 ? 0.42 : 0.18
  if (profile.host_interaction_profile.callback_strings.length > 0) confidence += 0.16
  if (profile.host_interaction_profile.host_hints.length > 0) confidence += 0.16
  return {
    callback_exports: profile.host_interaction_profile.callback_exports,
    callback_strings: profile.host_interaction_profile.callback_strings,
    host_hints: profile.host_interaction_profile.host_hints,
    confidence: Math.min(1, confidence),
  }
}

export function createDllExportProfileHandler(
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
      const input = DllExportProfileInputSchema.parse(args)
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
      const libraryLike = ['dll', '.net_library', 'library_like_pe'].includes(profile.binary_role)
      const payload = {
        sample_id: profile.sample_id,
        original_filename: profile.original_filename,
        binary_role: profile.binary_role,
        library_like: libraryLike,
        role_confidence: profile.role_confidence,
        export_surface: profile.export_surface,
        export_dispatch_profile: profile.export_dispatch_profile,
        host_interaction_profile: profile.host_interaction_profile,
        lifecycle_surface: buildLifecycleSurface(profile),
        class_factory_surface: buildClassFactorySurface(profile),
        callback_surface: buildCallbackSurface(profile),
        dll_entry_hints: collectDllEntryHints(profile),
        likely_entry_model: inferDllEntryModel(profile),
        analysis_priorities: dedupe([
          ...profile.analysis_priorities,
          'review_dllmain_lifecycle_and_attach_detach_side_effects',
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
