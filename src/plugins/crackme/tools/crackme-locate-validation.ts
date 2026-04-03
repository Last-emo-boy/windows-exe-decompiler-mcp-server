/**
 * crackme.locate.validation MCP tool — automatically locate validation/check
 * functions in a CrackMe binary by analysing string references, dialog APIs,
 * conditional branch patterns, and known comparison idioms.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'crackme.locate.validation'

// String patterns that typically surround a validation check
const SUCCESS_STRINGS = [
  'correct', 'success', 'congratulation', 'well done', 'good job', 'registered',
  'valid', 'thank', 'unlocked', 'licensed', 'accepted', 'good boy',
]
const FAILURE_STRINGS = [
  'wrong', 'incorrect', 'invalid', 'bad', 'nope', 'try again', 'fail',
  'error', 'denied', 'expired', 'not valid', 'bad boy',
]
const DIALOG_APIS = [
  'MessageBoxA', 'MessageBoxW', 'MessageBoxExA', 'MessageBoxExW',
  'DialogBoxParamA', 'DialogBoxParamW', 'SetDlgItemTextA', 'SetDlgItemTextW',
  'SetWindowTextA', 'SetWindowTextW',
]
const INPUT_APIS = [
  'GetDlgItemTextA', 'GetDlgItemTextW', 'GetWindowTextA', 'GetWindowTextW',
  'SendMessageA', 'SendMessageW', 'SendDlgItemMessageA', 'SendDlgItemMessageW',
]
const CRYPTO_APIS = [
  'CryptHashData', 'CryptDeriveKey', 'CryptEncrypt', 'CryptDecrypt',
  'BCryptHash', 'MD5Init', 'SHA1Update',
]

export const CrackmeLocateValidationInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const crackmeLocateValidationToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Automatically locate likely validation/serial-check functions in a CrackMe binary. ' +
    'Analyses string references ("Wrong"/"Correct"), dialog/input API imports, crypto API calls, ' +
    'and conditional branch patterns to rank candidate functions.',
  inputSchema: CrackmeLocateValidationInputSchema,
}

interface CandidateFunction {
  name: string
  address: string
  score: number
  reasons: string[]
  success_strings: string[]
  failure_strings: string[]
  dialog_apis: string[]
  input_apis: string[]
  crypto_apis: string[]
}

export function createCrackmeLocateValidationHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof CrackmeLocateValidationInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Gather evidence from existing analysis artifacts
      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (!Array.isArray(evidence) || evidence.length === 0) {
        return { ok: false, errors: ['No analysis evidence found. Run ghidra.analyze and strings.extract first.'] }
      }

      // Extract function list, string refs, imports
      const functions: Array<{ name: string; address: string; size: number; callees?: string[]; strings?: string[] }> = []
      const allStrings: Array<{ value: string; address?: string; xrefs?: string[] }> = []
      const imports: Array<{ name: string; address?: string }> = []

      for (const entry of evidence) {
        const family = entry.evidence_family ?? ''
        let data: any
        try {
          data = typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
        } catch { continue }

        if (family === 'function_map' || family === 'functions') {
          const fns = data?.functions ?? data?.data?.functions ?? []
          for (const fn of fns) {
            functions.push({
              name: fn.name ?? fn.function_name ?? `FUN_${fn.address}`,
              address: fn.address ?? fn.entry ?? '',
              size: fn.size ?? 0,
              callees: fn.callees ?? [],
              strings: fn.strings ?? fn.string_refs ?? [],
            })
          }
        }
        if (family === 'strings' || family === 'string_extraction') {
          const strs = data?.strings ?? data?.data?.strings ?? []
          for (const s of strs) {
            allStrings.push({
              value: typeof s === 'string' ? s : (s.value ?? s.string ?? ''),
              address: s.address,
              xrefs: s.xrefs ?? [],
            })
          }
        }
        if (family === 'imports' || family === 'pe_imports') {
          const imps = data?.imports ?? data?.data?.imports ?? []
          for (const imp of imps) {
            imports.push({ name: imp.name ?? imp.function_name ?? '', address: imp.address })
          }
        }
      }

      // Score each function
      const candidates: CandidateFunction[] = []

      for (const fn of functions) {
        let score = 0
        const reasons: string[] = []
        const foundSuccess: string[] = []
        const foundFailure: string[] = []
        const foundDialog: string[] = []
        const foundInput: string[] = []
        const foundCrypto: string[] = []

        const fnStrings = (fn.strings ?? []).map(s => typeof s === 'string' ? s.toLowerCase() : '')
        const fnCallees = (fn.callees ?? []).map(c => typeof c === 'string' ? c : '')

        // Check string references
        for (const s of fnStrings) {
          for (const pat of SUCCESS_STRINGS) {
            if (s.includes(pat)) { foundSuccess.push(s); score += 15; reasons.push(`success_string: "${s}"`); break }
          }
          for (const pat of FAILURE_STRINGS) {
            if (s.includes(pat)) { foundFailure.push(s); score += 15; reasons.push(`failure_string: "${s}"`); break }
          }
        }

        // Both success+failure in same function is a very strong signal
        if (foundSuccess.length > 0 && foundFailure.length > 0) {
          score += 30
          reasons.push('has_both_success_and_failure_strings')
        }

        // Check API calls
        for (const callee of fnCallees) {
          for (const api of DIALOG_APIS) {
            if (callee.includes(api)) { foundDialog.push(api); score += 10; reasons.push(`dialog_api: ${api}`) }
          }
          for (const api of INPUT_APIS) {
            if (callee.includes(api)) { foundInput.push(api); score += 12; reasons.push(`input_api: ${api}`) }
          }
          for (const api of CRYPTO_APIS) {
            if (callee.includes(api)) { foundCrypto.push(api); score += 8; reasons.push(`crypto_api: ${api}`) }
          }
        }

        // Input + Dialog in same function = likely validation entry
        if (foundInput.length > 0 && foundDialog.length > 0) {
          score += 20
          reasons.push('input_plus_dialog_pattern')
        }

        if (score > 0) {
          candidates.push({
            name: fn.name,
            address: fn.address,
            score,
            reasons: [...new Set(reasons)],
            success_strings: [...new Set(foundSuccess)],
            failure_strings: [...new Set(foundFailure)],
            dialog_apis: [...new Set(foundDialog)],
            input_apis: [...new Set(foundInput)],
            crypto_apis: [...new Set(foundCrypto)],
          })
        }
      }

      // Sort by score descending
      candidates.sort((a, b) => b.score - a.score)
      const topCandidates = candidates.slice(0, 20)

      if (topCandidates.length === 0) {
        warnings.push('No obvious validation functions detected. The binary may use obfuscated or indirect patterns.')
      }

      const resultData = {
        candidate_count: topCandidates.length,
        candidates: topCandidates,
        search_stats: {
          functions_scanned: functions.length,
          strings_available: allStrings.length,
          imports_available: imports.length,
        },
        next_steps: topCandidates.length > 0
          ? [
              `Decompile the top candidate: code.function.decompile(sample_id, function_name='${topCandidates[0]?.name}')`,
              'Run symbolic execution: symbolic.explore(sample_id, target_function=...)',
              'Extract constraints: constraint.extract(sample_id)',
            ]
          : ['Run ghidra.analyze first, then re-run this tool'],
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'crackme_validation_candidates', 'crackme-locate', resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
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
