/**
 * attack.map tool
 * Map static/simulated indicators to MITRE ATT&CK techniques with evidence links.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult , PluginToolDeps} from '../../sdk.js'
import { createTriageWorkflowHandler } from '../../../workflows/triage.js'
import { createPackerDetectHandler } from '../../../tools/packer-detect.js'

const TOOL_NAME = 'attack.map'

export const AttackMapInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  include_low_confidence: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include low-confidence ATT&CK mappings'),
  max_techniques: z.number().int().min(1).max(200).optional().default(50),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache in upstream analysis tools'),
})

export type AttackMapInput = z.infer<typeof AttackMapInputSchema>

const AttackTechniqueSchema = z.object({
  technique_id: z.string(),
  name: z.string(),
  tactics: z.array(z.string()),
  confidence: z.number(),
  confidence_level: z.enum(['low', 'medium', 'high']),
  evidence: z.array(z.string()),
  sources: z.array(z.string()),
  evidence_weights: z.object({
    import: z.number(),
    string: z.number(),
    runtime: z.number(),
  }),
  counter_evidence: z.array(z.string()).optional(),
})

const CapabilityClusterSchema = z.object({
  capability: z.string(),
  confidence: z.number(),
  indicators: z.array(z.string()),
})

export const AttackMapOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      techniques: z.array(AttackTechniqueSchema),
      capability_clusters: z.array(CapabilityClusterSchema),
      tactic_summary: z.record(z.number()),
      inference: z.object({
        classification: z.enum(['benign', 'suspicious', 'malicious', 'unknown']),
        summary: z.string(),
      }),
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

export const attackMapToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate MITRE ATT&CK technique mapping from triage indicators with evidence-linked confidence scoring.',
  inputSchema: AttackMapInputSchema,
  outputSchema: AttackMapOutputSchema,
}

export interface AttackIndicators {
  suspiciousImports: string[]
  suspiciousStrings: string[]
  commands: string[]
  urls: string[]
  ips: string[]
  registryKeys: string[]
  yaraMatches: string[]
  yaraLowConfidence: string[]
  packed: boolean
  packerConfidence: number
  runtimeHints?: string[]
  intentLabel?: 'dual_use_tool' | 'operator_utility' | 'malware_like_payload' | 'unknown'
  intentConfidence?: number
}

export interface AttackTechnique {
  technique_id: string
  name: string
  tactics: string[]
  confidence: number
  confidence_level: 'low' | 'medium' | 'high'
  evidence: string[]
  sources: string[]
  evidence_weights: {
    import: number
    string: number
    runtime: number
  }
  counter_evidence?: string[]
}

export interface CapabilityCluster {
  capability: string
  confidence: number
  indicators: string[]
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === 'string')
}

function normalizeImportApi(importRef: string): string {
  const last = importRef.split('!').pop() || importRef
  return last.toLowerCase()
}

function buildCapabilityClusters(indicators: AttackIndicators): CapabilityCluster[] {
  const clusters: CapabilityCluster[] = []
  const normalizedApis = indicators.suspiciousImports.map(normalizeImportApi)

  const injectionHits = normalizedApis.filter((api) =>
    ['writeprocessmemory', 'createremotethread', 'virtualallocex', 'setwindowshookex'].some(
      (needle) => api.includes(needle)
    )
  )
  if (injectionHits.length > 0) {
    clusters.push({
      capability: 'process_injection',
      confidence: 0.85,
      indicators: injectionHits.slice(0, 8),
    })
  }

  const commandHits = [
    ...normalizedApis.filter((api) =>
      ['createprocess', 'winexec', 'shellexecute'].some((needle) => api.includes(needle))
    ),
    ...indicators.commands.map((cmd) => cmd.toLowerCase()),
  ]
  if (commandHits.length > 0) {
    clusters.push({
      capability: 'command_execution',
      confidence: 0.72,
      indicators: Array.from(new Set(commandHits)).slice(0, 8),
    })
  }

  const networkHits = [
    ...normalizedApis.filter((api) =>
      ['internetopen', 'internetconnect', 'httpsendrequest', 'urldownloadtofile'].some((needle) =>
        api.includes(needle)
      )
    ),
    ...indicators.urls,
    ...indicators.ips,
  ]
  if (networkHits.length > 0) {
    clusters.push({
      capability: 'network_communication',
      confidence: 0.74,
      indicators: Array.from(new Set(networkHits)).slice(0, 10),
    })
  }

  const registryHits = [
    ...normalizedApis.filter((api) =>
      ['regsetvalue', 'regcreatekey'].some((needle) => api.includes(needle))
    ),
    ...indicators.registryKeys,
  ]
  if (registryHits.length > 0) {
    clusters.push({
      capability: 'registry_modification',
      confidence: 0.68,
      indicators: Array.from(new Set(registryHits)).slice(0, 8),
    })
  }

  if (indicators.packed || indicators.packerConfidence >= 0.58) {
    clusters.push({
      capability: 'defense_evasion_or_packing',
      confidence: Math.max(0.62, Math.min(indicators.packerConfidence, 0.92)),
      indicators: ['packed_or_obfuscated_binary'],
    })
  }

  return clusters
}

function normalizeWeights(weights: { import: number; string: number; runtime: number }): {
  import: number
  string: number
  runtime: number
} {
  const safe = {
    import: Math.max(0, weights.import),
    string: Math.max(0, weights.string),
    runtime: Math.max(0, weights.runtime),
  }
  const sum = safe.import + safe.string + safe.runtime
  if (sum <= 0) {
    return { import: 0.34, string: 0.33, runtime: 0.33 }
  }
  return {
    import: Number((safe.import / sum).toFixed(2)),
    string: Number((safe.string / sum).toFixed(2)),
    runtime: Number((safe.runtime / sum).toFixed(2)),
  }
}

function estimateEvidenceWeights(
  technique: Omit<AttackTechnique, 'confidence_level'>,
  indicators: AttackIndicators
): { import: number; string: number; runtime: number } {
  const sourceSet = new Set(technique.sources.map((item) => item.toLowerCase()))
  let importWeight = sourceSet.has('imports') ? 0.7 : 0.15
  let stringWeight = sourceSet.has('strings') ? 0.7 : 0.2
  let runtimeWeight = sourceSet.has('runtime') ? 0.7 : 0.15

  if (technique.sources.some((item) => item.toLowerCase().includes('packer'))) {
    runtimeWeight = Math.max(runtimeWeight, 0.4)
  }
  if ((indicators.runtimeHints || []).length > 0) {
    runtimeWeight += 0.2
  }

  const hasImportEvidence = technique.evidence.some((item) => item.includes('!'))
  if (!hasImportEvidence) {
    importWeight *= 0.6
  }
  if (indicators.suspiciousStrings.length === 0) {
    stringWeight *= 0.6
  }

  return normalizeWeights({
    import: importWeight,
    string: stringWeight,
    runtime: runtimeWeight,
  })
}

function upsertTechnique(
  map: Map<string, AttackTechnique>,
  technique: Omit<AttackTechnique, 'confidence_level' | 'evidence_weights'> & {
    evidence_weights?: { import: number; string: number; runtime: number }
  }
): void {
  const existing = map.get(technique.technique_id)
  if (!existing) {
    const level: AttackTechnique['confidence_level'] =
      technique.confidence >= 0.8 ? 'high' : technique.confidence >= 0.55 ? 'medium' : 'low'
    map.set(technique.technique_id, {
      ...technique,
      confidence: Number(technique.confidence.toFixed(2)),
      confidence_level: level,
      evidence: Array.from(new Set(technique.evidence)),
      sources: Array.from(new Set(technique.sources)),
      evidence_weights: normalizeWeights(
        technique.evidence_weights || { import: 0.34, string: 0.33, runtime: 0.33 }
      ),
      counter_evidence: technique.counter_evidence?.length
        ? Array.from(new Set(technique.counter_evidence))
        : undefined,
    })
    return
  }

  const mergedConfidence = Math.max(existing.confidence, technique.confidence)
  const mergedEvidence = Array.from(new Set([...existing.evidence, ...technique.evidence]))
  const mergedSources = Array.from(new Set([...existing.sources, ...technique.sources]))
  const level: AttackTechnique['confidence_level'] =
    mergedConfidence >= 0.8 ? 'high' : mergedConfidence >= 0.55 ? 'medium' : 'low'

  map.set(technique.technique_id, {
    ...existing,
    confidence: Number(mergedConfidence.toFixed(2)),
    confidence_level: level,
    evidence: mergedEvidence,
    sources: mergedSources,
    evidence_weights: normalizeWeights({
      import: Math.max(existing.evidence_weights.import, technique.evidence_weights?.import || 0),
      string: Math.max(existing.evidence_weights.string, technique.evidence_weights?.string || 0),
      runtime: Math.max(existing.evidence_weights.runtime, technique.evidence_weights?.runtime || 0),
    }),
    counter_evidence: Array.from(
      new Set([...(existing.counter_evidence || []), ...(technique.counter_evidence || [])])
    ),
  })
}

export function mapIndicatorsToAttack(
  indicators: AttackIndicators,
  options: { includeLowConfidence: boolean; maxTechniques: number }
): { techniques: AttackTechnique[]; capabilityClusters: CapabilityCluster[] } {
  const techniqueMap = new Map<string, AttackTechnique>()
  const normalizedApis = indicators.suspiciousImports.map(normalizeImportApi)
  const joinedStrings = indicators.suspiciousStrings.map((item) => item.toLowerCase()).join(' || ')
  const joinedCommands = indicators.commands.map((item) => item.toLowerCase()).join(' || ')
  const dualUseIntent = indicators.intentLabel === 'dual_use_tool'
  const operatorUtilityIntent = indicators.intentLabel === 'operator_utility'

  const injectionEvidence = indicators.suspiciousImports.filter((entry) =>
    ['writeprocessmemory', 'createremotethread', 'virtualallocex', 'setwindowshookex'].some(
      (needle) => normalizeImportApi(entry).includes(needle)
    )
  )
  if (injectionEvidence.length > 0) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1055',
      name: 'Process Injection',
      tactics: ['Defense Evasion', 'Privilege Escalation'],
      confidence: 0.86,
      evidence: injectionEvidence.slice(0, 8),
      sources: ['imports'],
    })
  }

  if (
    normalizedApis.some((api) =>
      ['createprocess', 'winexec', 'shellexecute'].some((needle) => api.includes(needle))
    ) || /cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe/.test(joinedCommands)
  ) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1059.003',
      name: 'Windows Command Shell',
      tactics: ['Execution'],
      confidence: 0.72,
      evidence: indicators.commands.slice(0, 6),
      sources: ['imports', 'strings'],
    })
  }

  if (/powershell\.exe/.test(joinedCommands) || /powershell/.test(joinedStrings)) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1059.001',
      name: 'PowerShell',
      tactics: ['Execution'],
      confidence: 0.76,
      evidence: indicators.commands.slice(0, 6),
      sources: ['strings'],
    })
  }

  const networkEvidence = [
    ...indicators.urls.slice(0, 6),
    ...indicators.ips.slice(0, 6),
    ...indicators.suspiciousImports
      .filter((entry) =>
        ['internetopen', 'internetconnect', 'httpsendrequest'].some((needle) =>
          normalizeImportApi(entry).includes(needle)
        )
      )
      .slice(0, 6),
  ]
  if (networkEvidence.length > 0) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1071.001',
      name: 'Application Layer Protocol: Web Protocols',
      tactics: ['Command and Control'],
      confidence: 0.74,
      evidence: networkEvidence,
      sources: ['imports', 'strings'],
    })
  }

  if (
    indicators.urls.length > 0 &&
    normalizedApis.some((api) => api.includes('urldownloadtofile'))
  ) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1105',
      name: 'Ingress Tool Transfer',
      tactics: ['Command and Control'],
      confidence: 0.71,
      evidence: [
        ...indicators.urls.slice(0, 4),
        ...indicators.suspiciousImports
          .filter((entry) => normalizeImportApi(entry).includes('urldownloadtofile'))
          .slice(0, 4),
      ],
      sources: ['imports', 'strings'],
    })
  }

  if (
    indicators.registryKeys.length > 0 ||
    normalizedApis.some((api) => api.includes('regsetvalue') || api.includes('regcreatekey'))
  ) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1112',
      name: 'Modify Registry',
      tactics: ['Defense Evasion', 'Persistence'],
      confidence: 0.69,
      evidence: [
        ...indicators.registryKeys.slice(0, 6),
        ...indicators.suspiciousImports
          .filter((entry) => {
            const api = normalizeImportApi(entry)
            return api.includes('regsetvalue') || api.includes('regcreatekey')
          })
          .slice(0, 4),
      ],
      sources: ['imports', 'strings'],
    })
  }

  if (indicators.packed || indicators.packerConfidence >= 0.58) {
    upsertTechnique(techniqueMap, {
      technique_id: 'T1027',
      name: 'Obfuscated/Compressed Files and Information',
      tactics: ['Defense Evasion'],
      confidence: Math.max(0.62, Math.min(indicators.packerConfidence, 0.9)),
      evidence: ['packer.detect signaled packing/obfuscation traits'],
      sources: ['packer.detect'],
    })
  }

  const highConfidenceRansomSignals = indicators.yaraMatches.filter(
    (rule) => rule.toLowerCase().includes('ransomware') || rule.toLowerCase().includes('encrypt')
  )
  const lowConfidenceRansomSignals = indicators.yaraLowConfidence.filter(
    (rule) => rule.toLowerCase().includes('ransomware') || rule.toLowerCase().includes('encrypt')
  )
  if (highConfidenceRansomSignals.length > 0 || lowConfidenceRansomSignals.length > 0) {
    const onlyWeakRansomSignals =
      highConfidenceRansomSignals.length === 0 && lowConfidenceRansomSignals.length > 0
    const counterEvidence: string[] = []
    let ransomwareConfidence = highConfidenceRansomSignals.length > 0 ? 0.78 : 0.34

    if (onlyWeakRansomSignals) {
      counterEvidence.push(
        'Only low-confidence/string-heavy ransomware YARA hints were present without stronger corroboration.'
      )
    }
    if (dualUseIntent) {
      ransomwareConfidence = Math.max(0.1, ransomwareConfidence - 0.16)
      counterEvidence.push(
        'Triage intent assessment suggests a dual-use operator tool, which weakens impact-only ransomware mapping.'
      )
    } else if (operatorUtilityIntent) {
      ransomwareConfidence = Math.max(0.1, ransomwareConfidence - 0.1)
      counterEvidence.push(
        'Operator-facing CLI/help surface reduces confidence that encryption-related strings imply destructive impact.'
      )
    }

    upsertTechnique(techniqueMap, {
      technique_id: 'T1486',
      name: 'Data Encrypted for Impact',
      tactics: ['Impact'],
      confidence: ransomwareConfidence,
      evidence: [...highConfidenceRansomSignals, ...lowConfidenceRansomSignals].slice(0, 6),
      sources: ['yara'],
      counter_evidence: counterEvidence.length > 0 ? counterEvidence : undefined,
    })
  }

  let techniques = Array.from(techniqueMap.values()).sort((a, b) => b.confidence - a.confidence)
  const networkApiPresent = indicators.suspiciousImports.some((entry) =>
    ['internetopen', 'internetconnect', 'httpsendrequest', 'urldownloadtofile'].some((needle) =>
      normalizeImportApi(entry).includes(needle)
    )
  )
  const noNetworkEvidence =
    indicators.urls.length === 0 && indicators.ips.length === 0 && !networkApiPresent
  const noCommandEvidence =
    indicators.commands.length === 0 &&
    !indicators.suspiciousImports.some((entry) =>
      ['createprocess', 'winexec', 'shellexecute'].some((needle) =>
        normalizeImportApi(entry).includes(needle)
      )
    )
  const staticOnlyAssessment = true

  techniques = techniques.map((technique) => {
    const counterEvidence = [...(technique.counter_evidence || [])]
    let adjustedConfidence = technique.confidence

    if (dualUseIntent && ['T1055', 'T1059.003', 'T1059.001'].includes(technique.technique_id)) {
      adjustedConfidence = Math.max(0.1, adjustedConfidence - 0.18)
      counterEvidence.push(
        'Triage intent assessment suggests a dual-use operator tool; downgraded static-only execution/injection mapping.'
      )
    } else if (
      operatorUtilityIntent &&
      ['T1055', 'T1059.003', 'T1059.001'].includes(technique.technique_id)
    ) {
      adjustedConfidence = Math.max(0.1, adjustedConfidence - 0.1)
      counterEvidence.push(
        'Operator-facing CLI/help surface reduces confidence that this static capability is malware-exclusive.'
      )
    }

    if (
      noNetworkEvidence &&
      (technique.technique_id === 'T1071.001' || technique.technique_id === 'T1105')
    ) {
      adjustedConfidence = Math.max(0.1, adjustedConfidence - 0.22)
      counterEvidence.push('Missing network import/URL/IP evidence for C2 behavior.')
    }

    if (
      noCommandEvidence &&
      (technique.technique_id === 'T1059.003' || technique.technique_id === 'T1059.001')
    ) {
      adjustedConfidence = Math.max(0.1, adjustedConfidence - 0.16)
      counterEvidence.push('Missing explicit command execution evidence.')
    }

    if (staticOnlyAssessment) {
      adjustedConfidence = Math.max(0.1, adjustedConfidence - 0.05)
      counterEvidence.push('No dynamic execution trace; static-only inference.')
    }

    const confidence_level: AttackTechnique['confidence_level'] =
      adjustedConfidence >= 0.8 ? 'high' : adjustedConfidence >= 0.55 ? 'medium' : 'low'

    return {
      ...technique,
      confidence: Number(adjustedConfidence.toFixed(2)),
      confidence_level,
      evidence_weights: estimateEvidenceWeights(technique, indicators),
      counter_evidence: Array.from(new Set(counterEvidence)).filter((item) => item.length > 0),
    }
  })

  if (!options.includeLowConfidence) {
    techniques = techniques.filter((tech) => tech.confidence_level !== 'low')
  }
  techniques = techniques.slice(0, options.maxTechniques)

  const capabilityClusters = buildCapabilityClusters(indicators)

  return { techniques, capabilityClusters }
}

function getClassification(
  threatLevel: string | undefined,
  techniqueCount: number,
  highConfidenceCount: number,
  intentLabel?: AttackIndicators['intentLabel']
): 'benign' | 'suspicious' | 'malicious' | 'unknown' {
  if (
    intentLabel === 'dual_use_tool' &&
    highConfidenceCount < 2 &&
    (threatLevel === 'malicious' || techniqueCount > 0)
  ) {
    return 'suspicious'
  }
  if (threatLevel === 'malicious' || highConfidenceCount >= 2) {
    return 'malicious'
  }
  if (threatLevel === 'suspicious' || techniqueCount > 0) {
    return 'suspicious'
  }
  if (threatLevel === 'clean') {
    return 'benign'
  }
  return 'unknown'
}

export function createAttackMapHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, cacheManager } = deps
  const triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
  const packerHandler = createPackerDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = AttackMapInputSchema.parse(args)
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

      const triageResult = await triageHandler({
        sample_id: input.sample_id,
        force_refresh: input.force_refresh,
      })
      if (!triageResult.ok || !triageResult.data) {
        return {
          ok: false,
          errors: triageResult.errors || ['workflow.triage failed'],
          warnings: triageResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const triageData = triageResult.data as {
        threat_level?: string
        iocs?: Record<string, unknown>
        raw_results?: Record<string, unknown>
        inference?: {
          intent_assessment?: {
            label?: AttackIndicators['intentLabel']
            confidence?: number
          }
        }
      }
      const iocs = (triageData.iocs || {}) as Record<string, unknown>
      const highValue = (iocs.high_value_iocs || {}) as Record<string, unknown>
      const runtimeRaw = (triageData.raw_results || {}).runtime as {
        suspected?: Array<{ runtime?: string }>
      } | null

      const packerResult = await packerHandler({
        sample_id: input.sample_id,
        force_refresh: input.force_refresh,
      })
      const packerData = (packerResult.data || {}) as { packed?: boolean; confidence?: number }

      const indicators: AttackIndicators = {
        suspiciousImports: toStringArray(iocs.suspicious_imports),
        suspiciousStrings: toStringArray(iocs.suspicious_strings),
        commands: toStringArray(highValue.commands),
        urls: toStringArray(iocs.urls),
        ips: toStringArray(iocs.ip_addresses),
        registryKeys: toStringArray(iocs.registry_keys),
        yaraMatches: toStringArray(iocs.yara_matches),
        yaraLowConfidence: toStringArray(iocs.yara_low_confidence),
        packed: Boolean(packerData.packed),
        packerConfidence:
          typeof packerData.confidence === 'number' ? Number(packerData.confidence) : 0,
        runtimeHints: Array.isArray(runtimeRaw?.suspected)
          ? runtimeRaw.suspected
              .map((item) => String(item.runtime || '').trim())
              .filter((item) => item.length > 0)
          : [],
        intentLabel: triageData.inference?.intent_assessment?.label || 'unknown',
        intentConfidence:
          typeof triageData.inference?.intent_assessment?.confidence === 'number'
            ? triageData.inference.intent_assessment.confidence
            : 0,
      }

      const mapping = mapIndicatorsToAttack(indicators, {
        includeLowConfidence: input.include_low_confidence,
        maxTechniques: input.max_techniques,
      })

      const tacticSummary: Record<string, number> = {}
      for (const technique of mapping.techniques) {
        for (const tactic of technique.tactics) {
          tacticSummary[tactic] = (tacticSummary[tactic] || 0) + 1
        }
      }

      const highConfidenceCount = mapping.techniques.filter(
        (technique) => technique.confidence_level === 'high'
      ).length
      const counterEvidenceCount = mapping.techniques.reduce(
        (count, technique) => count + (technique.counter_evidence?.length || 0),
        0
      )
      const classification = getClassification(
        triageData.threat_level,
        mapping.techniques.length,
        highConfidenceCount,
        indicators.intentLabel
      )
      const intentSummary =
        indicators.intentLabel && indicators.intentLabel !== 'unknown'
          ? ` Triage intent=${indicators.intentLabel}(${Number(indicators.intentConfidence || 0).toFixed(2)}).`
          : ''

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          techniques: mapping.techniques,
          capability_clusters: mapping.capabilityClusters,
          tactic_summary: tacticSummary,
          inference: {
            classification,
            summary:
              mapping.techniques.length > 0
                ? `Mapped ${mapping.techniques.length} ATT&CK technique(s) from correlated indicators; ` +
                  `applied ${counterEvidenceCount} counter-evidence factor(s).${intentSummary}`
                : 'No strong ATT&CK technique mapping from current evidence.',
          },
        },
        warnings: [
          ...(triageResult.warnings || []),
          ...(packerResult.warnings || []),
        ],
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
