/**
 * ioc.export tool
 * Export layered IOC data and optional ATT&CK mapping in JSON / CSV / STIX 2.1.
 */

import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef , PluginToolDeps} from '../../sdk.js'
import { createTriageWorkflowHandler } from '../../../workflows/triage.js'
import { createPackerDetectHandler } from '../../../tools/packer-detect.js'
import { mapIndicatorsToAttack, type AttackIndicators } from './attack-map.js'

const TOOL_NAME = 'ioc.export'
const TOOL_VERSION = '0.1.0'

export const IOCExportInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  format: z.enum(['json', 'csv', 'stix2']).optional().default('json'),
  include_attack_map: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include ATT&CK mapping block in export payload'),
  include_low_confidence: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include low-confidence IOC and ATT&CK records'),
  max_iocs: z.number().int().min(1).max(5000).optional().default(300),
  persist_artifact: z.boolean().optional().default(true),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache in upstream analysis tools'),
})

export type IOCExportInput = z.infer<typeof IOCExportInputSchema>

const IOCRecordSchema = z.object({
  type: z.string(),
  value: z.string(),
  confidence: z.enum(['high', 'medium', 'low']),
  source: z.string(),
  tags: z.array(z.string()),
})

export const IOCExportOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      format: z.enum(['json', 'csv', 'stix2']),
      tool_version: z.string(),
      ioc_count: z.number(),
      iocs: z.array(IOCRecordSchema),
      content: z.string(),
      mime_type: z.string(),
      attack_technique_count: z.number(),
      artifact: z
        .object({
          id: z.string(),
          path: z.string(),
          type: z.string(),
          sha256: z.string(),
          mime: z.string(),
        })
        .optional(),
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

export const iocExportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Export normalized IOC data and optional ATT&CK mapping as JSON, CSV, or STIX 2.1 bundle.',
  inputSchema: IOCExportInputSchema,
  outputSchema: IOCExportOutputSchema,
}

interface IOCRecord {
  type: string
  value: string
  confidence: 'high' | 'medium' | 'low'
  source: string
  tags: string[]
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === 'string')
}

function dedupeIOC(records: IOCRecord[]): IOCRecord[] {
  const map = new Map<string, IOCRecord>()
  for (const record of records) {
    const key = `${record.type}::${record.value.toLowerCase()}`
    const existing = map.get(key)
    if (!existing) {
      map.set(key, record)
      continue
    }

    const confidenceRank: Record<IOCRecord['confidence'], number> = {
      low: 1,
      medium: 2,
      high: 3,
    }
    const betterConfidence =
      confidenceRank[record.confidence] > confidenceRank[existing.confidence]
        ? record.confidence
        : existing.confidence
    map.set(key, {
      ...existing,
      confidence: betterConfidence,
      tags: Array.from(new Set([...existing.tags, ...record.tags])),
      source: Array.from(new Set([existing.source, record.source])).join('+'),
    })
  }
  return Array.from(map.values())
}

function collectIOCRecords(iocs: Record<string, unknown>, includeLow: boolean): IOCRecord[] {
  const records: IOCRecord[] = []
  const highValue = (iocs.high_value_iocs || {}) as Record<string, unknown>

  for (const value of toStringArray(iocs.urls)) {
    records.push({ type: 'url', value, confidence: 'high', source: 'triage.urls', tags: ['network'] })
  }
  for (const value of toStringArray(iocs.ip_addresses)) {
    records.push({ type: 'ipv4', value, confidence: 'high', source: 'triage.ip_addresses', tags: ['network'] })
  }
  for (const value of toStringArray(iocs.registry_keys)) {
    records.push({
      type: 'registry_key',
      value,
      confidence: 'medium',
      source: 'triage.registry_keys',
      tags: ['persistence'],
    })
  }
  for (const value of toStringArray(iocs.file_paths)) {
    records.push({
      type: 'file_path',
      value,
      confidence: 'medium',
      source: 'triage.file_paths',
      tags: ['filesystem'],
    })
  }
  for (const value of toStringArray(iocs.suspicious_imports)) {
    records.push({
      type: 'api',
      value,
      confidence: 'medium',
      source: 'triage.suspicious_imports',
      tags: ['api'],
    })
  }
  for (const value of toStringArray(highValue.commands)) {
    records.push({
      type: 'command',
      value,
      confidence: 'medium',
      source: 'triage.high_value_iocs.commands',
      tags: ['execution'],
    })
  }
  for (const value of toStringArray(highValue.pipes)) {
    records.push({
      type: 'pipe',
      value,
      confidence: 'medium',
      source: 'triage.high_value_iocs.pipes',
      tags: ['ipc'],
    })
  }
  for (const value of toStringArray(iocs.yara_matches)) {
    records.push({
      type: 'yara_rule',
      value,
      confidence: 'high',
      source: 'triage.yara_matches',
      tags: ['detection'],
    })
  }
  for (const value of toStringArray(iocs.yara_low_confidence)) {
    records.push({
      type: 'yara_rule',
      value,
      confidence: 'low',
      source: 'triage.yara_low_confidence',
      tags: ['detection', 'low_confidence'],
    })
  }

  let deduped = dedupeIOC(records)
  if (!includeLow) {
    deduped = deduped.filter((item) => item.confidence !== 'low')
  }
  return deduped
}

function csvEscape(value: string): string {
  if (value.includes('"') || value.includes(',') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

function toCSV(records: IOCRecord[]): string {
  const lines = ['type,value,confidence,source,tags']
  for (const record of records) {
    lines.push(
      [
        csvEscape(record.type),
        csvEscape(record.value),
        csvEscape(record.confidence),
        csvEscape(record.source),
        csvEscape(record.tags.join('|')),
      ].join(',')
    )
  }
  return lines.join('\n')
}

function normalizeStixTimestamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function buildIndicatorPattern(record: IOCRecord): string | null {
  const escaped = record.value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
  if (record.type === 'url') {
    return `[url:value = '${escaped}']`
  }
  if (record.type === 'ipv4' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(record.value)) {
    return `[ipv4-addr:value = '${escaped}']`
  }
  if (record.type === 'registry_key') {
    return `[windows-registry-key:key = '${escaped}']`
  }
  if (record.type === 'file_path') {
    const fileName = path.basename(record.value).replace(/\\/g, '\\\\').replace(/'/g, "\\'")
    return `[file:name = '${fileName}']`
  }
  if (record.type === 'command') {
    return `[process:command_line = '${escaped}']`
  }
  return null
}

function toSTIX(
  sampleId: string,
  records: IOCRecord[],
  attackTechniques: Array<{ technique_id: string; name: string; tactics: string[]; confidence: number }>
): string {
  const now = new Date()
  const created = normalizeStixTimestamp(now)
  const objects: Array<Record<string, unknown>> = []
  const objectRefs: string[] = []
  const indicatorIds: string[] = []

  for (const record of records) {
    const observedDataId = `observed-data--${randomUUID()}`
    const observedObjects: Record<string, unknown> = {
      '0': {
        type:
          record.type === 'url'
            ? 'url'
            : record.type === 'ipv4'
              ? 'ipv4-addr'
              : record.type === 'registry_key'
                ? 'windows-registry-key'
                : record.type === 'file_path'
                  ? 'file'
                  : record.type === 'command'
                    ? 'process'
                    : record.type === 'api'
                      ? 'x-mcp-api-call'
                      : record.type === 'pipe'
                        ? 'x-mcp-pipe'
                        : 'x-mcp-ioc',
        value: record.value,
        command_line: record.type === 'command' ? record.value : undefined,
        key: record.type === 'registry_key' ? record.value : undefined,
        name: record.type === 'file_path' ? path.basename(record.value) : record.value,
      },
    }
    objects.push({
      type: 'observed-data',
      spec_version: '2.1',
      id: observedDataId,
      created,
      modified: created,
      first_observed: created,
      last_observed: created,
      number_observed: 1,
      objects: observedObjects,
      labels: record.tags,
      x_mcp_source: record.source,
      x_mcp_confidence_level: record.confidence,
    })
    objectRefs.push(observedDataId)

    const pattern = buildIndicatorPattern(record)
    if (pattern) {
      const id = `indicator--${randomUUID()}`
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id,
        created,
        modified: created,
        name: `${record.type}:${record.value.slice(0, 80)}`,
        pattern_type: 'stix',
        pattern,
        valid_from: created,
        confidence: record.confidence === 'high' ? 80 : record.confidence === 'medium' ? 60 : 35,
        labels: record.tags,
      })
      objectRefs.push(id)
      indicatorIds.push(id)

      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${randomUUID()}`,
        created,
        modified: created,
        relationship_type: 'based-on',
        source_ref: id,
        target_ref: observedDataId,
      })
      continue
    }

    const noteId = `note--${randomUUID()}`
    objects.push({
      type: 'note',
      spec_version: '2.1',
      id: noteId,
      created,
      modified: created,
      abstract: `IOC (${record.type})`,
      content: `${record.value}\nsource=${record.source}\nconfidence=${record.confidence}`,
      labels: record.tags,
      object_refs: [observedDataId],
    })
    objectRefs.push(noteId)
  }

  for (const technique of attackTechniques) {
    const attackPatternId = `attack-pattern--${randomUUID()}`
    objects.push({
      type: 'attack-pattern',
      spec_version: '2.1',
      id: attackPatternId,
      created,
      modified: created,
      name: `${technique.technique_id} ${technique.name}`,
      external_references: [
        {
          source_name: 'mitre-attack',
          external_id: technique.technique_id,
          url: `https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`,
        },
      ],
      x_mcp_confidence: Number(technique.confidence.toFixed(2)),
      kill_chain_phases: technique.tactics.map((tactic) => ({
        kill_chain_name: 'mitre-attack',
        phase_name: tactic.toLowerCase().replace(/\s+/g, '-'),
      })),
    })
    objectRefs.push(attackPatternId)

    for (const indicatorId of indicatorIds.slice(0, 30)) {
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--${randomUUID()}`,
        created,
        modified: created,
        relationship_type: 'related-to',
        source_ref: attackPatternId,
        target_ref: indicatorId,
      })
    }
  }

  const reportId = `report--${randomUUID()}`
  objects.push({
    type: 'report',
    spec_version: '2.1',
    id: reportId,
    created,
    modified: created,
    name: `IOC export for ${sampleId}`,
    description: 'Generated by ioc.export tool',
    report_types: ['threat-report'],
    object_refs: objectRefs,
    published: created,
  })

  return JSON.stringify(
    {
      type: 'bundle',
      id: `bundle--${randomUUID()}`,
      spec_version: '2.1',
      objects,
    },
    null,
    2
  )
}

function formatContent(
  sampleId: string,
  format: IOCExportInput['format'],
  records: IOCRecord[],
  attackTechniques: Array<{ technique_id: string; name: string; tactics: string[]; confidence: number }>
): { content: string; mimeType: string; extension: string } {
  if (format === 'csv') {
    return {
      content: toCSV(records),
      mimeType: 'text/csv',
      extension: 'csv',
    }
  }

  if (format === 'stix2') {
    return {
      content: toSTIX(sampleId, records, attackTechniques),
      mimeType: 'application/stix+json',
      extension: 'json',
    }
  }

  return {
    content: JSON.stringify(
      {
        sample_id: sampleId,
        generated_at: new Date().toISOString(),
        iocs: records,
        attack_map: attackTechniques,
      },
      null,
      2
    ),
    mimeType: 'application/json',
    extension: 'json',
  }
}

export function createIOCExportHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, cacheManager } = deps
  const triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
  const packerHandler = createPackerDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = IOCExportInputSchema.parse(args)
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
        iocs?: Record<string, unknown>
      }
      const iocs = (triageData.iocs || {}) as Record<string, unknown>
      let records = collectIOCRecords(iocs, input.include_low_confidence)
      records = records.slice(0, input.max_iocs)

      let attackTechniques: Array<{
        technique_id: string
        name: string
        tactics: string[]
        confidence: number
      }> = []
      const warnings: string[] = [...(triageResult.warnings || [])]

      if (input.include_attack_map) {
        const highValue = (iocs.high_value_iocs || {}) as Record<string, unknown>
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
          runtimeHints: [],
        }

        const mapped = mapIndicatorsToAttack(indicators, {
          includeLowConfidence: input.include_low_confidence,
          maxTechniques: 80,
        })
        attackTechniques = mapped.techniques.map((item) => ({
          technique_id: item.technique_id,
          name: item.name,
          tactics: item.tactics,
          confidence: item.confidence,
        }))

        if (packerResult.warnings) {
          warnings.push(...packerResult.warnings)
        }
      }

      const formatted = formatContent(input.sample_id, input.format, records, attackTechniques)
      const artifacts: ArtifactRef[] = []
      let artifactRef: ArtifactRef | undefined

      if (input.persist_artifact) {
        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        const exportDir = path.join(workspace.reports, 'ioc_exports')
        await fs.mkdir(exportDir, { recursive: true })

        const fileName = `ioc_export_${Date.now()}.${formatted.extension}`
        const absPath = path.join(exportDir, fileName)
        await fs.writeFile(absPath, formatted.content, 'utf-8')

        const artifactId = randomUUID()
        const sha256 = createHash('sha256').update(formatted.content).digest('hex')
        const relativePath = `reports/ioc_exports/${fileName}`

        database.insertArtifact({
          id: artifactId,
          sample_id: input.sample_id,
          type: `ioc_export_${input.format}`,
          path: relativePath,
          sha256,
          mime: formatted.mimeType,
          created_at: new Date().toISOString(),
        })

        artifactRef = {
          id: artifactId,
          type: `ioc_export_${input.format}`,
          path: relativePath,
          sha256,
          mime: formatted.mimeType,
        }
        artifacts.push(artifactRef)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          format: input.format,
          tool_version: TOOL_VERSION,
          ioc_count: records.length,
          iocs: records,
          content: formatted.content,
          mime_type: formatted.mimeType,
          attack_technique_count: attackTechniques.length,
          artifact: artifactRef,
        },
        warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
        artifacts,
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
