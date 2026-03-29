import path from 'path'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import { generateCacheKey } from '../cache-manager.js'
import { formatCacheWarning } from './cache-observability.js'
import { createPEExportsExtractHandler } from './pe-exports-extract.js'
import { createPEImportsExtractHandler } from './pe-imports-extract.js'
import { createStringsExtractHandler } from './strings-extract.js'
import { createRuntimeDetectHandler } from './runtime-detect.js'
import { createPackerDetectHandler } from './packer-detect.js'
import {
  inspectSampleWorkspace,
  formatMissingOriginalError,
  resolvePrimarySamplePath,
} from '../sample-workspace.js'
import {
  buildDeferredToolResponse,
  shouldDeferLargeSample,
} from '../nonblocking-analysis.js'
import {
  AnalysisEvidenceStateSchema,
  buildDeferredEvidenceState,
  buildFreshEvidenceState,
  buildResolvedEvidenceState,
  buildEvidenceReuseWarnings,
  persistCanonicalEvidence,
  resolveCanonicalEvidenceOrCache,
} from '../analysis-evidence.js'

const TOOL_NAME = 'binary.role.profile'
const TOOL_VERSION = '0.2.0'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000

export const BinaryRoleProfileInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['fast', 'full'])
    .default('fast')
    .describe('fast reuses preview strings and bounded heuristics. Start with fast on medium or larger samples. full requests complete supporting evidence and may be deferred to the background queue.'),
  max_exports: z
    .number()
    .int()
    .min(1)
    .max(32)
    .default(12)
    .describe('Maximum notable exports returned in the summarized export surface'),
  max_strings: z
    .number()
    .int()
    .min(20)
    .max(400)
    .default(120)
    .describe('Maximum strings inspected for COM/service/plugin role heuristics'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
  defer_if_slow: z
    .boolean()
    .default(true)
    .describe('When true, mode=full may be deferred to the background queue instead of blocking the MCP request.'),
})

export const ExportSurfaceSchema = z.object({
  total_exports: z.number().int().nonnegative(),
  total_forwarders: z.number().int().nonnegative(),
  notable_exports: z.array(z.string()),
  com_related_exports: z.array(z.string()),
  service_related_exports: z.array(z.string()),
  plugin_related_exports: z.array(z.string()),
  forwarded_exports: z.array(z.string()),
})

export const ImportSurfaceSchema = z.object({
  dll_count: z.number().int().nonnegative(),
  notable_dlls: z.array(z.string()),
  com_related_imports: z.array(z.string()),
  service_related_imports: z.array(z.string()),
  network_related_imports: z.array(z.string()),
  process_related_imports: z.array(z.string()),
})

export const RoleIndicatorSchema = z.object({
  likely: z.boolean(),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
})

export const ExportDispatchProfileSchema = z.object({
  command_like_exports: z.array(z.string()),
  callback_like_exports: z.array(z.string()),
  registration_exports: z.array(z.string()),
  ordinal_only_exports: z.number().int().nonnegative(),
  likely_dispatch_model: z.string(),
  confidence: z.number().min(0).max(1),
})

export const ComProfileSchema = z.object({
  clsid_strings: z.array(z.string()),
  progid_strings: z.array(z.string()),
  interface_hints: z.array(z.string()),
  registration_strings: z.array(z.string()),
  class_factory_exports: z.array(z.string()),
  class_factory_surface: z.array(z.string()).default([]),
  confidence: z.number().min(0).max(1),
})

export const HostInteractionProfileSchema = z.object({
  likely_hosted: z.boolean(),
  host_hints: z.array(z.string()),
  callback_exports: z.array(z.string()),
  callback_surface: z.array(z.string()).default([]),
  callback_strings: z.array(z.string()),
  service_hooks: z.array(z.string()),
  confidence: z.number().min(0).max(1),
})

export const BinaryRoleProfileDataSchema = z.object({
  sample_id: z.string(),
  original_filename: z.string().nullable(),
  binary_role: z.string(),
  role_confidence: z.number().min(0).max(1),
  runtime_hint: z.object({
    is_dotnet: z.boolean().nullable(),
    dotnet_version: z.string().nullable(),
    target_framework: z.string().nullable(),
    primary_runtime: z.string().nullable(),
  }),
  export_surface: ExportSurfaceSchema,
  import_surface: ImportSurfaceSchema,
  packed: z.boolean(),
  packing_confidence: z.number().min(0).max(1),
  indicators: z.object({
    com_server: RoleIndicatorSchema,
    service_binary: RoleIndicatorSchema,
    plugin_binary: RoleIndicatorSchema,
    driver_binary: RoleIndicatorSchema,
  }),
  export_dispatch_profile: ExportDispatchProfileSchema,
  lifecycle_surface: z.array(z.string()).default([]),
  com_profile: ComProfileSchema,
  host_interaction_profile: HostInteractionProfileSchema,
  analysis_priorities: z.array(z.string()),
  strings_considered: z.number().int().nonnegative(),
})

export const BinaryRoleProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: BinaryRoleProfileDataSchema.partial()
    .extend({
      status: z.enum(['ready', 'queued', 'partial']).optional(),
      result_mode: z.enum(['fast', 'full']).optional(),
      execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export const binaryRoleProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Summarize Windows PE role, export surface, DLL/COM/service/plugin indicators, and analysis priorities for EXE/DLL-like samples. Start with mode=fast for normal or large samples, then escalate to mode=full only when export/import/string correlation must be complete.',
  inputSchema: BinaryRoleProfileInputSchema,
  outputSchema: BinaryRoleProfileOutputSchema,
}

type PEExportsData = {
  exports?: Array<{
    ordinal: number
    address: number
    name: string | null
  }>
  forwarders?: Array<{
    ordinal: number
    address: number
    name: string | null
    forwarder: string
  }>
  total_exports?: number
  total_forwarders?: number
}

type PEImportsData = {
  imports?: Record<string, string[]>
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
  dotnet_version?: string | null
  target_framework?: string | null
  suspected?: Array<{
    runtime: string
    confidence: number
    evidence: string[]
  }>
}

type PackerDetectData = {
  packed?: boolean
  confidence?: number
}

interface BinaryRoleProfileDependencies {
  exportsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  importsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  stringsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  runtimeHandler?: (args: ToolArgs) => Promise<WorkerResult>
  packerHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function clamp(value: number, min = 0, max = 1) {
  if (Number.isNaN(value)) {
    return min
  }
  return Math.min(max, Math.max(min, value))
}

function uniqueStrings(values: Array<string | null | undefined>) {
  const seen = new Set<string>()
  const output: string[] = []
  for (const value of values) {
    const trimmed = (value || '').trim()
    if (!trimmed) {
      continue
    }
    if (seen.has(trimmed)) {
      continue
    }
    seen.add(trimmed)
    output.push(trimmed)
  }
  return output
}

async function getOriginalFilename(
  workspaceManager: WorkspaceManager,
  sampleId: string
): Promise<string | null> {
  const { samplePath: primarySamplePath } = await resolvePrimarySamplePath(workspaceManager, sampleId)
  if (!primarySamplePath) {
    return null
  }
  return path.basename(primarySamplePath)
}

function inferBinaryRole(
  originalFilename: string | null,
  sampleFileType: string | null | undefined,
  exportCount: number,
  importsData: PEImportsData | undefined,
  runtimeData: RuntimeDetectData | undefined
): { binaryRole: string; roleConfidence: number; roleEvidence: string[] } {
  const loweredName = (originalFilename || '').toLowerCase()
  const loweredType = (sampleFileType || '').toLowerCase()
  const importDlls = Object.keys(importsData?.imports || {}).map((item) => item.toLowerCase())
  const evidence: string[] = []

  if (
    loweredName.endsWith('.sys') ||
    loweredType.includes('driver') ||
    importDlls.some((item) => item.includes('ntoskrnl') || item.includes('fltmgr'))
  ) {
    evidence.push('driver filename/type/import pattern')
    return { binaryRole: 'driver', roleConfidence: 0.96, roleEvidence: evidence }
  }

  if (runtimeData?.is_dotnet) {
    evidence.push('runtime.detect is_dotnet=true')
    if (loweredName.endsWith('.dll') || loweredType.includes('dll')) {
      evidence.push('dll filename/type')
      return { binaryRole: '.net_library', roleConfidence: 0.95, roleEvidence: evidence }
    }
    return { binaryRole: '.net_executable', roleConfidence: 0.94, roleEvidence: evidence }
  }

  if (
    loweredName.endsWith('.dll') ||
    loweredName.endsWith('.ocx') ||
    loweredName.endsWith('.cpl') ||
    loweredType.includes('dll')
  ) {
    evidence.push('dll-like filename/type')
    return { binaryRole: 'dll', roleConfidence: exportCount > 0 ? 0.92 : 0.84, roleEvidence: evidence }
  }

  if (loweredName.endsWith('.exe') || loweredType.includes('exe') || loweredType.includes('pe32')) {
    evidence.push('executable filename/type')
    return {
      binaryRole: exportCount > 0 ? 'executable_with_exports' : 'executable',
      roleConfidence: exportCount > 0 ? 0.8 : 0.88,
      roleEvidence: evidence,
    }
  }

  if (exportCount > 0) {
    evidence.push('exports present without clear filename/type')
    return { binaryRole: 'library_like_pe', roleConfidence: 0.73, roleEvidence: evidence }
  }

  return { binaryRole: 'pe_image', roleConfidence: 0.62, roleEvidence: ['generic PE image'] }
}

function buildRoleIndicator(
  confidence: number,
  evidence: string[]
): z.infer<typeof RoleIndicatorSchema> {
  return {
    likely: confidence >= 0.55,
    confidence: clamp(confidence),
    evidence: uniqueStrings(evidence),
  }
}

function flattenImportFunctions(importsData: PEImportsData | undefined): string[] {
  return uniqueStrings(
    Object.values(importsData?.imports || {})
      .flatMap((items) => items || [])
      .map((item) => item.trim())
  )
}

export function createBinaryRoleProfileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: BinaryRoleProfileDependencies,
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  const exportsHandler =
    dependencies?.exportsHandler ||
    createPEExportsExtractHandler(workspaceManager, database, cacheManager)
  const importsHandler =
    dependencies?.importsHandler ||
    createPEImportsExtractHandler(workspaceManager, database, cacheManager)
  const stringsHandler =
    dependencies?.stringsHandler ||
    createStringsExtractHandler(workspaceManager, database, cacheManager)
  const runtimeHandler =
    dependencies?.runtimeHandler ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const packerHandler =
    dependencies?.packerHandler ||
    createPackerDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = BinaryRoleProfileInputSchema.parse(args)
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

      const originalFilename = await getOriginalFilename(workspaceManager, input.sample_id)
      if (!originalFilename) {
        const integrity = await inspectSampleWorkspace(workspaceManager, input.sample_id)
        return {
          ok: false,
          errors: [formatMissingOriginalError(input.sample_id, integrity)],
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
          mode: input.mode,
          max_exports: input.max_exports,
          max_strings: input.max_strings,
          original_filename: originalFilename,
        },
      })

      if (!input.force_refresh) {
        const resolved = await resolveCanonicalEvidenceOrCache(database, cacheManager, cacheKey, {
          sample,
          evidenceFamily: 'binary_role',
          backend: TOOL_NAME,
          mode: input.mode,
          args: {
            max_exports: input.max_exports,
            max_strings: input.max_strings,
            original_filename: originalFilename,
          },
        })
        if (resolved) {
          return {
            ok: true,
            data: {
              ...(resolved.record.result as Record<string, unknown>),
              status: 'ready',
              result_mode: input.mode,
              execution_state: 'completed',
              evidence_state: [buildResolvedEvidenceState(resolved)],
            },
            warnings:
              resolved.source === 'cache' && resolved.cache
                ? [...buildEvidenceReuseWarnings(resolved), formatCacheWarning(resolved.cache.metadata)]
                : buildEvidenceReuseWarnings(resolved),
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: resolved.source === 'cache',
              cache_key: resolved.cache?.metadata.key,
              cache_tier: resolved.cache?.metadata.tier,
              cache_created_at: resolved.cache?.metadata.createdAt,
              cache_expires_at: resolved.cache?.metadata.expiresAt,
              cache_hit_at: resolved.cache?.metadata.fetchedAt,
            },
          }
        }
      }

      if (
        input.mode === 'full' &&
        input.defer_if_slow !== false &&
        jobQueue &&
        options.allowDeferred !== false &&
        shouldDeferLargeSample(sample, 'full')
      ) {
        return buildDeferredToolResponse({
          jobQueue,
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: {
            ...input,
            defer_if_slow: false,
          },
          timeoutMs: 5 * 60 * 1000,
          summary:
            'Full binary role profiling was deferred because it needs complete supporting strings and heuristic passes on a medium or larger sample.',
          nextTools: ['task.status', 'dll.export.profile', 'com.role.profile'],
          nextActions: [
            'Use mode=fast for an immediate role hint.',
            'Poll task.status with the returned job_id before requesting the same full role profile again.',
          ],
          metadata: {
            evidence_state: [
              buildDeferredEvidenceState({
                evidenceFamily: 'binary_role',
                backend: TOOL_NAME,
                mode: input.mode,
                reason:
                  'Full binary role profiling was deferred because the requested sample size exceeds the synchronous heuristic budget.',
              }),
            ],
          },
        })
      }

      const [exportsResult, importsResult, stringsResult, runtimeResult, packerResult] =
        await Promise.all([
          exportsHandler({ sample_id: input.sample_id, force_refresh: input.force_refresh }),
          importsHandler({
            sample_id: input.sample_id,
            group_by_dll: true,
            force_refresh: input.force_refresh,
          }),
          stringsHandler({
            sample_id: input.sample_id,
            mode: input.mode === 'fast' ? 'preview' : 'full',
            category_filter: 'all',
            max_strings: input.max_strings,
            force_refresh: input.force_refresh,
            defer_if_slow: false,
          }),
          runtimeHandler({ sample_id: input.sample_id, force_refresh: input.force_refresh }),
          packerHandler({ sample_id: input.sample_id, force_refresh: input.force_refresh }),
        ])

      const warnings = [
        ...(exportsResult.warnings || []).map((item) => `exports: ${item}`),
        ...(importsResult.warnings || []).map((item) => `imports: ${item}`),
        ...(stringsResult.warnings || []).map((item) => `strings: ${item}`),
        ...(runtimeResult.warnings || []).map((item) => `runtime: ${item}`),
        ...(packerResult.warnings || []).map((item) => `packer: ${item}`),
      ]

      const exportsData = (exportsResult.ok ? exportsResult.data : undefined) as PEExportsData | undefined
      const importsData = (importsResult.ok ? importsResult.data : undefined) as PEImportsData | undefined
      const stringsData = (stringsResult.ok ? stringsResult.data : undefined) as StringsData | undefined
      const runtimeData = (runtimeResult.ok ? runtimeResult.data : undefined) as RuntimeDetectData | undefined
      const packerData = (packerResult.ok ? packerResult.data : undefined) as PackerDetectData | undefined

      const exportEntries = exportsData?.exports || []
      const forwarders = exportsData?.forwarders || []
      const importDlls = Object.keys(importsData?.imports || {})
      const importFunctions = flattenImportFunctions(importsData)
      const stringValues = (stringsData?.strings || []).map((item) => item.string)
      const loweredStrings = stringValues.map((item) => item.toLowerCase())
      const exportNames = exportEntries.map((item) => item.name).filter(Boolean) as string[]
      const loweredExports = exportNames.map((item) => item.toLowerCase())
      const loweredImportDlls = importDlls.map((item) => item.toLowerCase())
      const loweredImportFunctions = importFunctions.map((item) => item.toLowerCase())

      const { binaryRole, roleConfidence, roleEvidence } = inferBinaryRole(
        originalFilename,
        sample.file_type,
        exportsData?.total_exports ?? exportEntries.length,
        importsData,
        runtimeData
      )

      const clsidStrings = uniqueStrings(
        stringValues.filter((item) => /\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}/i.test(item))
      ).slice(0, 6)
      const progIdStrings = uniqueStrings(
        stringValues.filter((item) => /progid|classfactory|iclassfactory|cocreateinstance|dllgetclassobject/i.test(item))
      ).slice(0, 6)
      const comExports = uniqueStrings(
        exportNames.filter((item) => /dll(getclassobject|canunloadnow|registerserver|unregisterserver)/i.test(item))
      )
      const serviceExports = uniqueStrings(
        exportNames.filter((item) => /servicemain|svcmain/i.test(item))
      )
      const pluginExports = uniqueStrings(
        exportNames.filter((item) => /plugin|addin|extension|initialize/i.test(item))
      )
      const commandLikeExports = uniqueStrings(
        exportNames.filter((item) => /dispatch|command|execute|handle|invoke|run|process|query/i.test(item))
      )
      const callbackLikeExports = uniqueStrings(
        exportNames.filter((item) => /callback|hook|notify|event|factory|attach|detach/i.test(item))
      )
      const registrationExports = uniqueStrings(
        exportNames.filter((item) => /dll(registerserver|unregisterserver|install)|register/i.test(item))
      )
      const forwardedExports = uniqueStrings(
        forwarders.map((item) => `${item.name || `ordinal_${item.ordinal}`} -> ${item.forwarder}`)
      ).slice(0, input.max_exports)

      const comImports = uniqueStrings(
        importDlls.filter((item) => /ole32|oleaut32|combase|rpcrt4/i.test(item))
      )
      const serviceImports = uniqueStrings(
        importDlls.filter((item) => /advapi32/i.test(item))
      )
      const networkImports = uniqueStrings(
        importDlls.filter((item) => /winhttp|wininet|ws2_32|dnsapi|urlmon/i.test(item))
      )
      const processImports = uniqueStrings(
        importDlls.filter((item) => /kernel32|ntdll|psapi|dbghelp/i.test(item))
      )

      const comEvidence = [
        ...roleEvidence.filter((item) => item.includes('dll')),
        ...comExports.map((item) => `export:${item}`),
        ...comImports.map((item) => `import:${item}`),
        ...clsidStrings.map((item) => `clsid:${item}`),
        ...progIdStrings.map((item) => `string:${item}`),
      ]
      let comScore = 0
      if (comExports.length > 0) comScore += 0.38
      if (comImports.length > 0) comScore += 0.18
      if (clsidStrings.length > 0) comScore += 0.22
      if (progIdStrings.length > 0) comScore += 0.18
      if (binaryRole === 'dll' || binaryRole === '.net_library') comScore += 0.08
      const interfaceHints = uniqueStrings(
        stringValues.filter((item) => /iunknown|idispatch|iclassfactory|ipropertypage|iprovid(e|er)|interface/i.test(item))
      ).slice(0, 8)
      const registrationStrings = uniqueStrings(
        stringValues.filter((item) => /inprocserver32|localserver32|typelib|appid|clsid|progid|treatas/i.test(item))
      ).slice(0, 8)

      const serviceStrings = uniqueStrings(
        stringValues.filter((item) => /services\\|registerservicectrlhandler|startservicectrldispatcher|setservicestatus|servicemain/i.test(item))
      ).slice(0, 6)
      const serviceEvidence = [
        ...serviceImports.map((item) => `import:${item}`),
        ...serviceExports.map((item) => `export:${item}`),
        ...serviceStrings.map((item) => `string:${item}`),
      ]
      let serviceScore = 0
      if (serviceImports.length > 0) serviceScore += 0.28
      if (serviceStrings.length > 0) serviceScore += 0.24
      if (serviceExports.length > 0) serviceScore += 0.18
      if (loweredStrings.some((item) => item.includes('currentcontrolset\\services'))) serviceScore += 0.16

      const pluginStrings = uniqueStrings(
        stringValues.filter((item) => /plugin|extension|addin|host application|register plugin/i.test(item))
      ).slice(0, 6)
      const pluginEvidence = [
        ...pluginExports.map((item) => `export:${item}`),
        ...pluginStrings.map((item) => `string:${item}`),
      ]
      let pluginScore = 0
      if (pluginExports.length > 0) pluginScore += 0.34
      if (pluginStrings.length > 0) pluginScore += 0.22
      if ((binaryRole === 'dll' || binaryRole === '.net_library') && (pluginExports.length > 0 || pluginStrings.length > 0)) {
        pluginScore += 0.16
      }
      if (loweredExports.some((item) => item.includes('initialize'))) pluginScore += 0.1

      const hostHints = uniqueStrings(
        [
          ...stringValues.filter((item) => /plugin host|host application|shell extension|addin|extension point|loaded by/i.test(item)),
          ...importDlls.filter((item) => /shell32|explorerframe|office|vbscript|jscript/i.test(item)),
        ]
      ).slice(0, 8)
      const callbackStrings = uniqueStrings(
        stringValues.filter((item) => /callback|event sink|notification|hook chain|observer/i.test(item))
      ).slice(0, 8)
      const serviceHooks = uniqueStrings(
        [
          ...serviceExports,
          ...importFunctions.filter((item) => /startservicectrldispatcher|registerservicectrlhandler|setservicestatus/i.test(item)),
        ]
      ).slice(0, 8)
      let hostInteractionScore = 0
      if (pluginScore >= 0.4) hostInteractionScore += 0.25
      if (callbackLikeExports.length > 0) hostInteractionScore += 0.18
      if (callbackStrings.length > 0) hostInteractionScore += 0.16
      if (hostHints.length > 0) hostInteractionScore += 0.18
      if (serviceHooks.length > 0) hostInteractionScore += 0.12

      let exportDispatchScore = 0
      if (commandLikeExports.length > 0) exportDispatchScore += 0.34
      if (callbackLikeExports.length > 0) exportDispatchScore += 0.18
      if (forwardedExports.length > 0) exportDispatchScore += 0.08
      if (registrationExports.length > 0) exportDispatchScore += 0.14
      if ((exportsData?.total_exports ?? exportEntries.length) >= 8) exportDispatchScore += 0.12

      const ordinalOnlyExports = Math.max(
        0,
        (exportsData?.total_exports ?? exportEntries.length) - exportNames.length
      )

      let likelyDispatchModel = 'none'
      if (registrationExports.length > 0 && comScore >= 0.55) {
        likelyDispatchModel = 'com_registration_and_class_factory'
      } else if (pluginScore >= 0.55 && hostInteractionScore >= 0.45) {
        likelyDispatchModel = 'plugin_initialization_and_host_callbacks'
      } else if (commandLikeExports.length > 0) {
        likelyDispatchModel = 'exported_command_dispatch'
      } else if (forwardedExports.length > 0) {
        likelyDispatchModel = 'forwarded_export_surface'
      }

      const driverEvidence = uniqueStrings([
        ...roleEvidence.filter((item) => item.includes('driver')),
        ...loweredImportDlls.filter((item) => item.includes('ntoskrnl') || item.includes('fltmgr')).map((item) => `import:${item}`),
      ])
      let driverScore = 0
      if (binaryRole === 'driver') driverScore += 0.62
      if (driverEvidence.length > 1) driverScore += 0.2

      const priorities: string[] = []
      if (binaryRole === 'driver') priorities.push('review_driver_entrypoints_and_ioctl_surface')
      if (comScore >= 0.55) priorities.push('trace_com_activation_and_class_factory_flow')
      if (registrationExports.length > 0) priorities.push('review_registration_exports_and_inprocserver_paths')
      if (serviceScore >= 0.55) priorities.push('trace_service_entrypoint_and_scm_lifecycle')
      if (pluginScore >= 0.55) priorities.push('trace_host_plugin_exports_and_callback_model')
      if (exportDispatchScore >= 0.5) priorities.push('review_exported_command_dispatch_surface')
      if (hostInteractionScore >= 0.5) priorities.push('identify_host_callbacks_and_extension_contract')
      if (loweredImportFunctions.some((item) => item.includes('disablethreadlibrarycalls'))) {
        priorities.push('review_dllmain_lifecycle_and_attach_detach_side_effects')
      }
      if ((exportsData?.total_exports ?? exportEntries.length) > 0) priorities.push('trace_export_surface_first')
      if ((exportsData?.total_forwarders ?? forwarders.length) > 0) priorities.push('inspect_forwarded_exports')
      if (runtimeData?.is_dotnet) priorities.push('prefer_managed_metadata_and_il_recovery')
      if (packerData?.packed || (packerData?.confidence || 0) >= 0.45) priorities.push('unpack_or_stage_memory_import_before_deep_reconstruct')
      if (networkImports.length > 0) priorities.push('review_network_session_setup_and_remote_endpoints')
      if (processImports.length > 0) priorities.push('review_process_manipulation_and_dynamic_resolution_paths')

      const lifecycleSurface = uniqueStrings([
        ...exportNames.filter((item) => /dllmain|dllentry|initialize/i.test(item)),
        ...importFunctions.filter((item) => /disablethreadlibrarycalls|getmodulehandle|freelibrary/i.test(item)),
        ...stringValues.filter((item) => /dllmain|dll_process_attach|dll_process_detach|thread_attach|thread_detach/i.test(item)),
      ]).slice(0, input.max_exports)

      const classFactorySurface = uniqueStrings([
        ...comExports,
        ...interfaceHints.filter((item) => /iclassfactory|iunknown|idispatch/i.test(item)),
        ...stringValues.filter((item) => /createinstance|lockserver|dllgetclassobject|cocreateinstance/i.test(item)),
      ]).slice(0, input.max_exports)

      const callbackSurface = uniqueStrings([
        ...callbackLikeExports,
        ...callbackStrings,
        ...hostHints.filter((item) => /plugin|extension|host/i.test(item)),
      ]).slice(0, input.max_exports)

      const payload = {
        sample_id: input.sample_id,
        original_filename: originalFilename,
        binary_role: binaryRole,
        role_confidence: clamp(roleConfidence),
        runtime_hint: {
          is_dotnet: runtimeData?.is_dotnet ?? null,
          dotnet_version: runtimeData?.dotnet_version ?? null,
          target_framework: runtimeData?.target_framework ?? null,
          primary_runtime:
            [...(runtimeData?.suspected || [])].sort((a, b) => b.confidence - a.confidence)[0]?.runtime ||
            null,
        },
        export_surface: {
          total_exports: exportsData?.total_exports ?? exportEntries.length,
          total_forwarders: exportsData?.total_forwarders ?? forwarders.length,
          notable_exports: uniqueStrings(exportNames).slice(0, input.max_exports),
          com_related_exports: comExports.slice(0, input.max_exports),
          service_related_exports: serviceExports.slice(0, input.max_exports),
          plugin_related_exports: pluginExports.slice(0, input.max_exports),
          forwarded_exports: forwardedExports,
        },
        import_surface: {
          dll_count: importDlls.length,
          notable_dlls: uniqueStrings(importDlls).slice(0, input.max_exports),
          com_related_imports: comImports,
          service_related_imports: serviceImports,
          network_related_imports: networkImports,
          process_related_imports: processImports,
        },
        packed: packerData?.packed === true,
        packing_confidence: clamp(packerData?.confidence || 0),
        indicators: {
          com_server: buildRoleIndicator(comScore, comEvidence),
          service_binary: buildRoleIndicator(serviceScore, serviceEvidence),
          plugin_binary: buildRoleIndicator(pluginScore, pluginEvidence),
          driver_binary: buildRoleIndicator(driverScore, driverEvidence),
        },
        export_dispatch_profile: {
          command_like_exports: commandLikeExports.slice(0, input.max_exports),
          callback_like_exports: callbackLikeExports.slice(0, input.max_exports),
          registration_exports: registrationExports.slice(0, input.max_exports),
          ordinal_only_exports: ordinalOnlyExports,
          likely_dispatch_model: likelyDispatchModel,
          confidence: clamp(exportDispatchScore),
        },
        lifecycle_surface: lifecycleSurface,
        com_profile: {
          clsid_strings: clsidStrings,
          progid_strings: progIdStrings,
          interface_hints: interfaceHints,
          registration_strings: registrationStrings,
          class_factory_exports: comExports.slice(0, input.max_exports),
          class_factory_surface: classFactorySurface,
          confidence: clamp(comScore),
        },
        host_interaction_profile: {
          likely_hosted: hostInteractionScore >= 0.55,
          host_hints: hostHints,
          callback_exports: callbackLikeExports.slice(0, input.max_exports),
          callback_surface: callbackSurface,
          callback_strings: callbackStrings,
          service_hooks: serviceHooks,
          confidence: clamp(hostInteractionScore),
        },
        analysis_priorities: uniqueStrings(priorities).slice(0, 8),
        strings_considered: stringValues.length,
      }

      await cacheManager.setCachedResult(cacheKey, payload, CACHE_TTL_MS, sample.sha256)
      persistCanonicalEvidence(database, {
        sample,
        evidenceFamily: 'binary_role',
        backend: TOOL_NAME,
        mode: input.mode,
        args: {
          max_exports: input.max_exports,
          max_strings: input.max_strings,
          original_filename: originalFilename,
        },
        result: payload,
        metadata: {
          cache_key: cacheKey,
          original_filename: originalFilename,
        },
        provenance: {
          tool: TOOL_NAME,
          tool_version: TOOL_VERSION,
          precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
        },
      })

      return {
        ok: true,
        data: {
          ...payload,
          status: 'ready',
          result_mode: input.mode,
          execution_state: 'completed',
          evidence_state: [
            buildFreshEvidenceState({
              evidenceFamily: 'binary_role',
              backend: TOOL_NAME,
              mode: input.mode,
            }),
          ],
        },
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
