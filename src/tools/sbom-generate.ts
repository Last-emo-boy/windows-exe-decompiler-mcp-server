/**
 * MCP tool: sbom.generate
 *
 * Generates a Software Bill of Materials (SBOM) for a sample in CycloneDX JSON format.
 * Extracts components from PE imports, .NET references, embedded version info, and static analysis.
 */

import { z } from 'zod'
import crypto from 'crypto'
import type { ToolDefinition, ToolResult } from '../types.js'
import type { MCPServer } from '../server.js'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'

const inputSchema = z.object({
  sample_id: z.string().describe('Sample ID to generate SBOM for'),
  format: z.enum(['cyclonedx', 'spdx-lite']).optional().default('cyclonedx').describe('SBOM format (default: cyclonedx)'),
  include_hashes: z.boolean().optional().default(true).describe('Include file hashes'),
})

export const sbomGenerateToolDefinition: ToolDefinition = {
  name: 'sbom.generate',
  description: 'Generate a Software Bill of Materials (SBOM) for a binary sample. Extracts component dependencies from PE imports, .NET assemblies, embedded resources, and static analysis results. Output in CycloneDX JSON or SPDX-lite format.',
  inputSchema: inputSchema as any,
}

interface SbomComponent {
  type: string
  name: string
  version?: string
  purl?: string
  hashes?: Array<{ alg: string; content: string }>
  evidence?: { source: string }
}

export function createSbomGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof inputSchema>): Promise<ToolResult> => {
    const components: SbomComponent[] = []

    // 1. Query PE imports from the database
    try {
      const imports = database.querySql(
        'SELECT DISTINCT library FROM pe_imports WHERE sample_id = ?',
        [args.sample_id]
      ) as Array<{ library: string }>

      for (const imp of imports) {
        components.push({
          type: 'library',
          name: imp.library.replace(/\.dll$/i, ''),
          evidence: { source: 'pe-import-table' },
        })
      }
    } catch {
      // Table may not exist yet — that's okay
    }

    // 2. Query .NET assembly references
    try {
      const refs = database.querySql(
        'SELECT DISTINCT name, version FROM dotnet_references WHERE sample_id = ?',
        [args.sample_id]
      ) as Array<{ name: string; version?: string }>

      for (const ref of refs) {
        components.push({
          type: 'framework',
          name: ref.name,
          version: ref.version,
          evidence: { source: 'dotnet-metadata' },
        })
      }
    } catch {
      // Table may not exist
    }

    // 3. Query string-based dependency evidence
    try {
      const strings = database.querySql(
        `SELECT DISTINCT value FROM strings_cache WHERE sample_id = ? AND (
          value LIKE '%.dll' OR value LIKE '%.sys' OR value LIKE '%Version=%'
        ) LIMIT 200`,
        [args.sample_id]
      ) as Array<{ value: string }>

      for (const s of strings) {
        const val = s.value.trim()
        if (/\.(dll|sys)$/i.test(val) && val.length < 100 && !val.includes(' ')) {
          components.push({
            type: 'library',
            name: val,
            evidence: { source: 'embedded-string' },
          })
        }
      }
    } catch {
      // Table may not exist
    }

    // 4. Query sample hashes if requested
    let sampleHashes: Array<{ alg: string; content: string }> = []
    if (args.include_hashes) {
      try {
        const hashRow = database.querySql(
          'SELECT sha256, md5 FROM samples WHERE id = ?',
          [args.sample_id]
        ) as Array<{ sha256?: string; md5?: string }>

        if (hashRow.length > 0) {
          if (hashRow[0].sha256) sampleHashes.push({ alg: 'SHA-256', content: hashRow[0].sha256 })
          if (hashRow[0].md5) sampleHashes.push({ alg: 'MD5', content: hashRow[0].md5 })
        }
      } catch {
        // Skip hash lookup failures
      }
    }

    // Deduplicate components by name
    const seen = new Set<string>()
    const deduped = components.filter(c => {
      const key = `${c.type}:${c.name.toLowerCase()}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })

    // Build SBOM
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`
    const timestamp = new Date().toISOString()

    let sbom: unknown

    if (args.format === 'cyclonedx') {
      sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber,
        version: 1,
        metadata: {
          timestamp,
          tools: [{ vendor: 'rikune', name: 'sbom.generate', version: '1.0.0' }],
          component: {
            type: 'application',
            name: args.sample_id,
            hashes: sampleHashes.length > 0 ? sampleHashes : undefined,
          },
        },
        components: deduped.map((c, i) => ({
          'bom-ref': `comp-${i}`,
          type: c.type,
          name: c.name,
          version: c.version || undefined,
          purl: c.purl || undefined,
          hashes: c.hashes,
          evidence: c.evidence ? { occurrences: [{ location: c.evidence.source }] } : undefined,
        })),
      }
    } else {
      // spdx-lite
      sbom = {
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: `sbom-${args.sample_id}`,
        documentNamespace: serialNumber,
        creationInfo: {
          created: timestamp,
          creators: ['Tool: rikune-sbom-1.0.0'],
        },
        packages: deduped.map((c, i) => ({
          SPDXID: `SPDXRef-Package-${i}`,
          name: c.name,
          versionInfo: c.version || 'NOASSERTION',
          downloadLocation: 'NOASSERTION',
          filesAnalyzed: false,
        })),
      }
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(sbom, null, 2) }],
      structuredContent: sbom as Record<string, unknown>,
    }
  }
}
