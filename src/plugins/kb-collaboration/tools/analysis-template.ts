/**
 * analysis.template MCP tool — Apply a pre-defined analysis template
 * to a sample. Templates define ordered sequences of tools to execute
 * for common analysis workflows (malware triage, CTF solve, etc.)
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'analysis.template'

export const AnalysisTemplateInputSchema = z.object({
  template: z
    .enum([
      'malware_triage',
      'malware_deep',
      'crackme_solve',
      'packer_unpack',
      'vulnerability_audit',
      'android_apk',
      'firmware_analysis',
      'custom',
    ])
    .describe('Pre-defined analysis template to apply'),
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  custom_steps: z
    .array(z.string())
    .optional()
    .describe('Custom tool names to run in sequence (only for "custom" template)'),
})

export const analysisTemplateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Get a recommended analysis plan from a pre-defined template. Returns an ordered ' +
    'list of tools to call for common workflows like malware triage, CrackMe solving, ' +
    'or APK analysis. Use with analyze.pipeline for automated execution.',
  inputSchema: AnalysisTemplateInputSchema,
}

interface TemplateStep {
  tool: string
  description: string
  required: boolean
  depends_on?: string[]
  args_hint?: Record<string, unknown>
}

const TEMPLATES: Record<string, TemplateStep[]> = {
  malware_triage: [
    { tool: 'sample.ingest', description: 'Ingest sample into workspace', required: true },
    { tool: 'pe.fingerprint', description: 'Basic PE fingerprint (hashes, header)', required: true },
    { tool: 'compiler.packer.detect', description: 'Detect compiler and packer', required: true },
    { tool: 'static.capability.triage', description: 'Identify capabilities (network, crypto, anti-debug)', required: true },
    { tool: 'strings.extract', description: 'Extract ASCII/Unicode strings', required: true },
    { tool: 'yara.scan', description: 'Scan with YARA rules', required: false },
    { tool: 'pe.imports.extract', description: 'Extract import table', required: true },
    { tool: 'c2.extract', description: 'Extract C2 indicators', required: false, depends_on: ['strings.extract'] },
    { tool: 'malware.classify', description: 'Classify malware family', required: false },
    { tool: 'attack.map', description: 'Map to MITRE ATT&CK', required: false, depends_on: ['static.capability.triage'] },
    { tool: 'ioc.export', description: 'Export IoCs', required: false },
    { tool: 'report.summarize', description: 'Generate analysis summary', required: false },
  ],
  malware_deep: [
    { tool: 'sample.ingest', description: 'Ingest sample', required: true },
    { tool: 'pe.fingerprint', description: 'PE fingerprint', required: true },
    { tool: 'compiler.packer.detect', description: 'Compiler/packer detection', required: true },
    { tool: 'unpack.auto', description: 'Auto-unpack if packed', required: false, depends_on: ['compiler.packer.detect'] },
    { tool: 'static.capability.triage', description: 'Capability triage', required: true },
    { tool: 'pe.imports.extract', description: 'Import table analysis', required: true },
    { tool: 'pe.exports.extract', description: 'Export table analysis', required: false },
    { tool: 'strings.extract', description: 'String extraction', required: true },
    { tool: 'strings.floss.decode', description: 'Decode obfuscated strings (FLOSS)', required: false },
    { tool: 'ghidra.analyze', description: 'Full Ghidra analysis', required: true },
    { tool: 'code.functions.list', description: 'List all functions', required: true, depends_on: ['ghidra.analyze'] },
    { tool: 'crypto.identify', description: 'Identify crypto constants', required: false },
    { tool: 'malware.config.extract', description: 'Extract malware config', required: false },
    { tool: 'c2.extract', description: 'C2 extraction', required: false },
    { tool: 'sandbox.execute', description: 'Sandbox execution', required: false },
    { tool: 'sandbox.report', description: 'Sandbox behavior report', required: false, depends_on: ['sandbox.execute'] },
    { tool: 'behavior.timeline', description: 'Behavior timeline', required: false, depends_on: ['sandbox.execute'] },
    { tool: 'data.flow.map', description: 'Data flow analysis', required: false },
    { tool: 'attack.map', description: 'MITRE ATT&CK mapping', required: false },
    { tool: 'report.html.generate', description: 'Full HTML report', required: false },
  ],
  crackme_solve: [
    { tool: 'sample.ingest', description: 'Ingest CrackMe binary', required: true },
    { tool: 'pe.fingerprint', description: 'PE fingerprint', required: true },
    { tool: 'compiler.packer.detect', description: 'Check for packing', required: true },
    { tool: 'strings.extract', description: 'Extract strings (success/failure messages)', required: true },
    { tool: 'pe.imports.extract', description: 'Import analysis', required: true },
    { tool: 'ghidra.analyze', description: 'Ghidra analysis', required: true },
    { tool: 'crackme.locate.validation', description: 'Locate validation function', required: true, depends_on: ['ghidra.analyze'] },
    { tool: 'code.function.decompile', description: 'Decompile validation function', required: true, depends_on: ['crackme.locate.validation'], args_hint: { function_address: '<from locate.validation>' } },
    { tool: 'constraint.extract', description: 'Extract input constraints from validation', required: false },
    { tool: 'smt.solve', description: 'Solve constraints for valid key', required: false, depends_on: ['constraint.extract'] },
    { tool: 'symbolic.explore', description: 'Symbolic execution to find success path', required: false },
    { tool: 'patch.generate', description: 'Generate bypass patch', required: false, depends_on: ['crackme.locate.validation'] },
    { tool: 'keygen.verify', description: 'Verify candidate key', required: false },
  ],
  packer_unpack: [
    { tool: 'sample.ingest', description: 'Ingest packed binary', required: true },
    { tool: 'pe.fingerprint', description: 'PE fingerprint', required: true },
    { tool: 'compiler.packer.detect', description: 'Identify packer', required: true },
    { tool: 'pe.structure.analyze', description: 'Section entropy analysis', required: true },
    { tool: 'packer.detect', description: 'Detailed packer signatures', required: false },
    { tool: 'unpack.auto', description: 'Auto-unpack attempt', required: true, depends_on: ['compiler.packer.detect'] },
    { tool: 'strings.extract', description: 'Extract strings from unpacked', required: false, depends_on: ['unpack.auto'] },
    { tool: 'pe.imports.extract', description: 'Recover import table', required: false, depends_on: ['unpack.auto'] },
  ],
  vulnerability_audit: [
    { tool: 'sample.ingest', description: 'Ingest binary', required: true },
    { tool: 'pe.fingerprint', description: 'Fingerprint', required: true },
    { tool: 'pe.imports.extract', description: 'Import analysis', required: true },
    { tool: 'static.capability.triage', description: 'Capability triage', required: true },
    { tool: 'ghidra.analyze', description: 'Ghidra analysis', required: true },
    { tool: 'vuln.pattern.scan', description: 'Scan for vulnerability patterns', required: true, depends_on: ['ghidra.analyze'] },
    { tool: 'vuln.pattern.summary', description: 'Summarize findings', required: false, depends_on: ['vuln.pattern.scan'] },
    { tool: 'code.functions.rank', description: 'Rank functions by risk', required: false },
    { tool: 'crypto.identify', description: 'Check crypto usage', required: false },
  ],
  android_apk: [
    { tool: 'sample.ingest', description: 'Ingest APK', required: true },
    { tool: 'apk.structure.analyze', description: 'Analyze APK structure', required: true },
    { tool: 'apk.packer.detect', description: 'Detect APK packer/protector', required: true },
    { tool: 'dex.classes.list', description: 'List DEX classes', required: true },
    { tool: 'dex.decompile', description: 'Decompile DEX to Java', required: true },
    { tool: 'strings.extract', description: 'Extract strings', required: false },
    { tool: 'yara.scan', description: 'YARA scan', required: false },
  ],
  firmware_analysis: [
    { tool: 'sample.ingest', description: 'Ingest firmware image', required: true },
    { tool: 'strings.extract', description: 'Extract strings', required: true },
    { tool: 'elf.structure.analyze', description: 'Analyze ELF structure', required: false },
    { tool: 'elf.imports.extract', description: 'Extract ELF imports', required: false },
    { tool: 'ghidra.analyze', description: 'Ghidra analysis', required: false },
    { tool: 'crypto.identify', description: 'Identify crypto usage', required: false },
    { tool: 'vuln.pattern.scan', description: 'Vulnerability scan', required: false },
  ],
}

export function createAnalysisTemplateHandler(deps: PluginToolDeps) {
  const { database } = deps

  return async (args: z.infer<typeof AnalysisTemplateInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      let steps: TemplateStep[]

      if (args.template === 'custom') {
        if (!args.custom_steps?.length) {
          return { ok: false, errors: ['custom_steps required when template is "custom"'] }
        }
        steps = args.custom_steps.map((tool, i) => ({
          tool,
          description: `Step ${i + 1}: ${tool}`,
          required: true,
        }))
      } else {
        steps = TEMPLATES[args.template]
        if (!steps) return { ok: false, errors: [`Unknown template: ${args.template}`] }
      }

      // Check which steps have already been completed
      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      const completedFamilies = new Set<string>()
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          if (entry.evidence_family) completedFamilies.add(entry.evidence_family)
        }
      }

      // Map tool names to likely evidence families
      const toolToFamily: Record<string, string[]> = {
        'pe.fingerprint': ['pe_fingerprint'],
        'pe.imports.extract': ['pe_imports'],
        'pe.exports.extract': ['pe_exports'],
        'strings.extract': ['strings'],
        'static.capability.triage': ['capability_triage', 'static_triage'],
        'compiler.packer.detect': ['compiler_detect', 'packer_detect'],
        'ghidra.analyze': ['ghidra_functions', 'function_index'],
        'yara.scan': ['yara_scan'],
        'sandbox.execute': ['sandbox_execution'],
      }

      const plan = steps.map((step) => {
        const families = toolToFamily[step.tool] ?? []
        const alreadyDone = families.some((f) => completedFamilies.has(f))
        return {
          ...step,
          status: alreadyDone ? 'completed' : 'pending',
        }
      })

      const pendingCount = plan.filter((s) => s.status === 'pending').length

      return {
        ok: true,
        data: {
          template: args.template,
          sample_id: args.sample_id,
          total_steps: plan.length,
          pending_steps: pendingCount,
          completed_steps: plan.length - pendingCount,
          plan,
        },
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
