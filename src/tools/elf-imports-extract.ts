/**
 * elf.imports.extract MCP tool — extract ELF dynamic imports (DT_NEEDED + PLT symbols).
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import { resolvePackagePath } from '../runtime-paths.js'

const TOOL_NAME = 'elf.imports.extract'

export const ElfImportsExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const ElfImportsExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const elfImportsExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Extract ELF imports: DT_NEEDED shared libraries and imported symbols from .dynsym.',
  inputSchema: ElfImportsExtractInputSchema,
  outputSchema: ElfImportsExtractOutputSchema,
}

export function createElfImportsExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof ElfImportsExtractInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      const parsed = await callElfMachoWorker({ action: 'parse_elf', file_path: samplePath })

      if (!parsed.ok) {
        return { ok: false, errors: [String(parsed.error || 'ELF parsing failed')] }
      }

      // Extract DT_NEEDED entries
      const dynamic = (parsed.dynamic as Array<{ tag: string; value: string }>) || []
      const needed = dynamic
        .filter((d) => d.tag === 'DT_NEEDED')
        .map((d) => d.value)

      // Extract imported symbols (UND binding from dynsym)
      const symbols = (parsed.symbols as Array<{ name: string; type: string; bind: string; value: number }>) || []
      const importedSymbols = symbols
        .filter((s) => s.value === 0 && s.name && s.bind !== 'LOCAL')
        .map((s) => ({ name: s.name, type: s.type, bind: s.bind }))

      const importData = {
        needed_libraries: needed,
        imported_symbols: importedSymbols,
        total_needed: needed.length,
        total_imported_symbols: importedSymbols.length,
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, args.sample_id, 'elf_imports', 'elf-imports', importData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: importData,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}

async function callElfMachoWorker(request: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'elf_macho_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
    const proc = spawn(pythonCommand, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })

    let stdout = ''
    let stderr = ''

    proc.stdout.on('data', (d) => { stdout += d.toString() })
    proc.stderr.on('data', (d) => { stderr += d.toString() })

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker exited with code ${code}: ${stderr}`))
        return
      }
      try {
        const lines = stdout.trim().split('\n')
        resolve(JSON.parse(lines[lines.length - 1]))
      } catch (e) {
        reject(new Error(`Failed to parse worker response: ${(e as Error).message}`))
      }
    })

    proc.on('error', (e) => reject(new Error(`Failed to spawn worker: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}
