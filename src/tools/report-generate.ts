/**
 * report.generate MCP Tool
 * 
 * Requirements: 24.1, 24.3, 24.5, 24.6
 * 
 * Generates comprehensive Markdown analysis report
 */

import { z } from 'zod';
import fs from 'fs';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js';
import type { CacheManager } from '../cache-manager.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import { logger } from '../logger.js';
import { isGhidraReadyStatus } from '../ghidra-analysis-status.js';
import { loadDynamicTraceEvidence, type DynamicTraceSummary } from '../dynamic-trace.js';
import { loadSemanticFunctionExplanationIndex } from '../semantic-name-suggestion-artifacts.js';
import {
  loadStaticAnalysisArtifactSelection,
  STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
  PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
  COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
} from '../static-analysis-artifacts.js';
import {
  BinaryRoleProfileDataSchema,
  createBinaryRoleProfileHandler,
} from './binary-role-profile.js';
import {
  RustBinaryAnalyzeDataSchema,
  createRustBinaryAnalyzeHandler,
} from './rust-binary-analyze.js';
import { StaticCapabilityTriageDataSchema } from './static-capability-triage.js';
import { PEStructureAnalyzeDataSchema } from '../plugins/pe-analysis/tools/pe-structure-analyze.js';
import { CompilerPackerDetectDataSchema } from './compiler-packer-detect.js';
import { buildReportConfidenceSemantics } from '../confidence-semantics.js';
import {
  buildRuntimeArtifactProvenance,
  buildStaticArtifactProvenance,
  buildSemanticArtifactProvenance,
} from '../analysis-provenance.js';
import {
  buildArtifactSelectionDiff,
} from '../selection-diff.js';
import {
  GhidraExecutionSummarySchema,
  buildGhidraExecutionSummary,
} from '../ghidra-execution-summary.js';
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js';

/**
 * Input schema for report.generate tool
 */
export const reportGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  format: z.enum(['markdown', 'json', 'html']).optional().describe('Report format (default: markdown)'),
  include_sections: z.array(z.string()).optional().describe('Sections to include (default: all)'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('all')
    .describe('Runtime evidence scope: all artifacts, latest artifact window, or a specific session selector'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  static_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('latest')
    .describe('Static-analysis artifact scope shared by capability triage, PE structure analysis, and compiler/packer attribution selections'),
  static_session_tag: z
    .string()
    .optional()
    .describe('Optional static-analysis session selector used when static_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .default('all')
    .describe('Semantic explanation artifact scope: all artifacts, latest explanation window, or a specific semantic review session'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic review session selector used when semantic_scope=session or to narrow all/latest results'),
  compare_evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline runtime evidence scope used to compare this report against another runtime artifact selection'),
  compare_evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline runtime evidence session selector used when compare_evidence_scope=session'),
  compare_static_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline static-analysis scope used to compare capability, PE structure, and compiler/packer selections'),
  compare_static_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline static-analysis session selector used when compare_static_scope=session'),
  compare_semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .optional()
    .describe('Optional baseline semantic explanation scope used to compare this report against another semantic artifact selection'),
  compare_semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional baseline semantic explanation session selector used when compare_semantic_scope=session'),
}).refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
  message: 'evidence_session_tag is required when evidence_scope=session',
  path: ['evidence_session_tag'],
}).refine((value) => value.static_scope !== 'session' || Boolean(value.static_session_tag?.trim()), {
  message: 'static_session_tag is required when static_scope=session',
  path: ['static_session_tag'],
}).refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
  message: 'semantic_session_tag is required when semantic_scope=session',
  path: ['semantic_session_tag'],
}).refine(
  (value) =>
    value.compare_evidence_scope !== 'session' || Boolean(value.compare_evidence_session_tag?.trim()),
  {
    message: 'compare_evidence_session_tag is required when compare_evidence_scope=session',
    path: ['compare_evidence_session_tag'],
  }
).refine(
  (value) =>
    value.compare_static_scope !== 'session' || Boolean(value.compare_static_session_tag?.trim()),
  {
    message: 'compare_static_session_tag is required when compare_static_scope=session',
    path: ['compare_static_session_tag'],
  }
).refine(
  (value) =>
    value.compare_semantic_scope !== 'session' || Boolean(value.compare_semantic_session_tag?.trim()),
  {
    message: 'compare_semantic_session_tag is required when compare_semantic_scope=session',
    path: ['compare_semantic_session_tag'],
  }
);

export type ReportGenerateInput = z.infer<typeof reportGenerateInputSchema>;

export const reportGenerateOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    artifact_id: z.string(),
    path: z.string(),
    format: z.enum(['markdown', 'json', 'html']),
    size: z.number(),
    sha256: z.string(),
    tool_surface_role: ToolSurfaceRoleSchema,
    preferred_primary_tools: z.array(z.string()),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
    explanation_artifact_refs: z
      .array(
        z.object({
          id: z.string(),
          type: z.string(),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
          metadata: z.any().optional(),
        })
      )
      .optional(),
    provenance: z.any().optional(),
    ghidra_execution: GhidraExecutionSummarySchema.nullable().optional(),
    selection_diffs: z.any().optional(),
  }).optional(),
  errors: z.array(z.string()).optional(),
});

/**
 * Tool definition for report.generate
 */
export const reportGenerateToolDefinition: ToolDefinition = {
  name: 'report.generate',
  description:
    'Export a comprehensive archival report artifact in Markdown, JSON, or HTML. This is an export-only surface over already persisted analysis state, not the primary AI-facing staged summary flow. ' +
    'Prefer workflow.summarize for staged analyst synthesis and report.summarize for deterministic compact compatibility snapshots.',
  inputSchema: reportGenerateInputSchema,
  outputSchema: reportGenerateOutputSchema,
};

/**
 * Generate Markdown report
 */
function generateMarkdownReport(
  sample: any,
  analyses: any[],
  functions: any[],
  dynamicEvidence: DynamicTraceSummary | null,
  binaryProfile: z.infer<typeof BinaryRoleProfileDataSchema> | null,
  rustProfile: z.infer<typeof RustBinaryAnalyzeDataSchema> | null,
  staticCapabilities: z.infer<typeof StaticCapabilityTriageDataSchema> | null,
  peStructure: z.infer<typeof PEStructureAnalyzeDataSchema> | null,
  compilerPacker: z.infer<typeof CompilerPackerDetectDataSchema> | null,
  functionExplanations: Array<{
    address: string | null;
    function: string | null;
    behavior: string;
    summary: string;
    confidence: number;
    rewrite_guidance: string[];
    source: string | null;
  }>,
  evidenceScope: 'all' | 'latest' | 'session',
  evidenceSessionTag?: string,
  staticScope: 'all' | 'latest' | 'session' = 'latest',
  staticSessionTag?: string,
  semanticScope: 'all' | 'latest' | 'session' = 'all',
  semanticSessionTag?: string,
  provenance?: {
    runtime: ReturnType<typeof buildRuntimeArtifactProvenance>;
    static_capabilities: ReturnType<typeof buildStaticArtifactProvenance>;
    pe_structure: ReturnType<typeof buildStaticArtifactProvenance>;
    compiler_packer: ReturnType<typeof buildStaticArtifactProvenance>;
    semantic_explanations: ReturnType<typeof buildSemanticArtifactProvenance>;
  },
  ghidraExecution?: z.infer<typeof GhidraExecutionSummarySchema> | null,
  selectionDiffs?: {
    runtime?: ReturnType<typeof buildArtifactSelectionDiff>;
    static_capabilities?: ReturnType<typeof buildArtifactSelectionDiff>;
    pe_structure?: ReturnType<typeof buildArtifactSelectionDiff>;
    compiler_packer?: ReturnType<typeof buildArtifactSelectionDiff>;
    semantic_explanations?: ReturnType<typeof buildArtifactSelectionDiff>;
  }
): string {
  const lines: string[] = [];

  // Header
  lines.push(`# Analysis Report: ${sample.sha256}`);
  lines.push('');
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push('');

  // Sample Information
  lines.push('## Sample Information');
  lines.push('');
  lines.push(`- **SHA256:** ${sample.sha256}`);
  lines.push(`- **MD5:** ${sample.md5}`);
  lines.push(`- **Size:** ${sample.size} bytes`);
  lines.push(`- **File Type:** ${sample.file_type || 'Unknown'}`);
  lines.push(`- **Ingested:** ${sample.created_at}`);
  lines.push('');

  // Analysis Summary
  lines.push('## Analysis Summary');
  lines.push('');
  lines.push(`- **Total Analyses:** ${analyses.length}`);
  lines.push(`- **Completed:** ${analyses.filter(a => isGhidraReadyStatus(a.status)).length}`);
  lines.push(`- **Failed:** ${analyses.filter(a => a.status === 'failed').length}`);
  lines.push('');

  // Analyses Details
  for (const analysis of analyses) {
    lines.push(`### ${analysis.stage} (${analysis.backend})`);
    lines.push('');
    lines.push(`- **Status:** ${analysis.status}`);
    lines.push(`- **Started:** ${analysis.started_at || 'N/A'}`);
    lines.push(`- **Finished:** ${analysis.finished_at || 'N/A'}`);

    if (analysis.metrics_json) {
      try {
        const metrics = JSON.parse(analysis.metrics_json);
        lines.push(`- **Duration:** ${metrics.elapsed_ms}ms`);
      } catch (e) {
        // Ignore parse errors
      }
    }

    if (analysis.output_json) {
      try {
        const output = JSON.parse(analysis.output_json);
        if (output.function_count !== undefined) {
          lines.push(`- **Functions Extracted:** ${output.function_count}`);
        }
      } catch (e) {
        // Ignore parse errors
      }
    }

    lines.push('');
  }

  // Function Statistics
  if (functions.length > 0) {
    lines.push('## Function Statistics');
    lines.push('');
    lines.push(`- **Total Functions:** ${functions.length}`);

    const avgSize = functions.reduce((sum, f) => sum + (f.size || 0), 0) / functions.length;
    lines.push(`- **Average Size:** ${Math.round(avgSize)} bytes`);

    const entryPoints = functions.filter(f => f.is_entry_point === 1).length;
    lines.push(`- **Entry Points:** ${entryPoints}`);

    const exported = functions.filter(f => f.is_exported === 1).length;
    lines.push(`- **Exported Functions:** ${exported}`);

    lines.push('');

    // Top Functions
    const topFunctions = functions
      .filter(f => f.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);

    if (topFunctions.length > 0) {
      lines.push('### Top 10 Functions by Interest Score');
      lines.push('');
      lines.push('| Rank | Address | Name | Score | Tags |');
      lines.push('|------|---------|------|-------|------|');

      topFunctions.forEach((func, index) => {
        const tags = func.tags ? JSON.parse(func.tags).join(', ') : '';
        lines.push(`| ${index + 1} | ${func.address} | ${func.name || 'unknown'} | ${func.score.toFixed(2)} | ${tags} |`);
      });

      lines.push('');
    }
  }

  if (binaryProfile) {
    const lifecycleSurface = binaryProfile.lifecycle_surface || [];
    const classFactorySurface = binaryProfile.com_profile.class_factory_surface || [];
    const callbackSurface = binaryProfile.host_interaction_profile.callback_surface || [];
    lines.push('## Binary Role Profile');
    lines.push('');
    lines.push(`- **Binary Role:** ${binaryProfile.binary_role}`);
    lines.push(`- **Role Confidence:** ${binaryProfile.role_confidence.toFixed(2)}`);
    lines.push(`- **Packed:** ${binaryProfile.packed ? 'Yes' : 'No'}`);
    lines.push(`- **Packing Confidence:** ${binaryProfile.packing_confidence.toFixed(2)}`);
    lines.push(`- **Exports:** ${binaryProfile.export_surface.total_exports}`);
    lines.push(`- **Forwarded Exports:** ${binaryProfile.export_surface.total_forwarders}`);
    lines.push(`- **Import DLL Count:** ${binaryProfile.import_surface.dll_count}`);
    if (binaryProfile.export_surface.notable_exports.length > 0) {
      lines.push(`- **Notable Exports:** ${binaryProfile.export_surface.notable_exports.join(', ')}`);
    }
    if (binaryProfile.import_surface.notable_dlls.length > 0) {
      lines.push(`- **Notable DLLs:** ${binaryProfile.import_surface.notable_dlls.join(', ')}`);
    }
    if (binaryProfile.export_dispatch_profile.likely_dispatch_model !== 'none') {
      lines.push(`- **Likely Dispatch Model:** ${binaryProfile.export_dispatch_profile.likely_dispatch_model}`);
    }
    if (binaryProfile.export_dispatch_profile.registration_exports.length > 0) {
      lines.push(`- **Registration Exports:** ${binaryProfile.export_dispatch_profile.registration_exports.join(', ')}`);
    }
    if (lifecycleSurface.length > 0) {
      lines.push(`- **DLL Lifecycle Surface:** ${lifecycleSurface.join(', ')}`);
    }
    if (binaryProfile.com_profile.class_factory_exports.length > 0) {
      lines.push(`- **Class Factory Exports:** ${binaryProfile.com_profile.class_factory_exports.join(', ')}`);
    }
    if (classFactorySurface.length > 0) {
      lines.push(`- **Class Factory Surface:** ${classFactorySurface.join(', ')}`);
    }
    if (binaryProfile.com_profile.interface_hints.length > 0) {
      lines.push(`- **COM Interface Hints:** ${binaryProfile.com_profile.interface_hints.join(', ')}`);
    }
    if (binaryProfile.com_profile.registration_strings.length > 0) {
      lines.push(`- **COM Registration Strings:** ${binaryProfile.com_profile.registration_strings.join(', ')}`);
    }
    if (binaryProfile.host_interaction_profile.callback_exports.length > 0) {
      lines.push(`- **Callback Exports:** ${binaryProfile.host_interaction_profile.callback_exports.join(', ')}`);
    }
    if (callbackSurface.length > 0) {
      lines.push(`- **Callback Surface:** ${callbackSurface.join(', ')}`);
    }
    if (binaryProfile.host_interaction_profile.callback_strings.length > 0) {
      lines.push(`- **Callback Strings:** ${binaryProfile.host_interaction_profile.callback_strings.join(', ')}`);
    }
    if (binaryProfile.host_interaction_profile.service_hooks.length > 0) {
      lines.push(`- **Service Hooks:** ${binaryProfile.host_interaction_profile.service_hooks.join(', ')}`);
    }
    if (binaryProfile.host_interaction_profile.host_hints.length > 0) {
      lines.push(`- **Host Hints:** ${binaryProfile.host_interaction_profile.host_hints.join(', ')}`);
    }
    if (binaryProfile.analysis_priorities.length > 0) {
      lines.push(`- **Analysis Priorities:** ${binaryProfile.analysis_priorities.join(', ')}`);
    }
    lines.push('');
  }

  if (rustProfile) {
    lines.push('## Rust Binary Profile');
    lines.push('');
    lines.push(`- **Suspected Rust:** ${rustProfile.suspected_rust ? 'Yes' : 'No'}`);
    lines.push(`- **Rust Confidence:** ${rustProfile.confidence.toFixed(2)}`);
    lines.push(`- **Primary Runtime:** ${rustProfile.primary_runtime || 'N/A'}`);
    lines.push(`- **Recovered Functions:** ${rustProfile.recovered_function_count}`);
    lines.push(`- **Recovered Symbols:** ${rustProfile.recovered_symbol_count}`);
    if (rustProfile.crate_hints.length > 0) {
      lines.push(`- **Crate Hints:** ${rustProfile.crate_hints.join(', ')}`);
    }
    if (rustProfile.cargo_paths.length > 0) {
      lines.push(`- **Cargo Paths:** ${rustProfile.cargo_paths.slice(0, 4).join(', ')}`);
    }
    if (rustProfile.runtime_hints.length > 0) {
      lines.push(`- **Runtime Hints:** ${rustProfile.runtime_hints.join(', ')}`);
    }
    if (rustProfile.analysis_priorities.length > 0) {
      lines.push(`- **Analysis Priorities:** ${rustProfile.analysis_priorities.join(', ')}`);
    }
    lines.push('');
  }

  lines.push('## Static Analysis');
  lines.push('');
  lines.push(`- **Static Scope:** ${staticScope}`);
  lines.push(`- **Static Session Selector:** ${staticSessionTag || 'N/A'}`);
  if (staticCapabilities) {
    lines.push(`- **Capability Findings:** ${staticCapabilities.capability_count}`);
    lines.push(`- **Capability Namespaces:** ${staticCapabilities.behavior_namespaces.join(', ') || 'none'}`);
  } else {
    lines.push('- **Capability Findings:** none');
  }
  if (peStructure) {
    lines.push(
      `- **PE Structure Summary:** sections=${peStructure.summary.section_count}, imports=${peStructure.summary.import_function_count}, exports=${peStructure.summary.export_count}, resources=${peStructure.summary.resource_count}, overlay=${peStructure.summary.overlay_present ? 'yes' : 'no'}`
    );
  } else {
    lines.push('- **PE Structure Summary:** none');
  }
  if (compilerPacker) {
    lines.push(
      `- **Compiler/Packer Attribution:** compiler=${compilerPacker.summary.compiler_count}, packer=${compilerPacker.summary.packer_count}, protector=${compilerPacker.summary.protector_count}, file_type=${compilerPacker.summary.likely_primary_file_type || 'unknown'}`
    );
  } else {
    lines.push('- **Compiler/Packer Attribution:** none');
  }
  lines.push('');

  lines.push('## Runtime Evidence');
  lines.push('');
  lines.push(`- **Evidence Scope:** ${evidenceScope}`);
  lines.push(`- **Session Selector:** ${evidenceSessionTag || 'N/A'}`);

  if (dynamicEvidence) {
    lines.push(`- **Artifacts Considered:** ${dynamicEvidence.artifact_count}`);
    lines.push(`- **Executed Trace Present:** ${dynamicEvidence.executed ? 'Yes' : 'No'}`);
    lines.push(`- **Latest Imported At:** ${dynamicEvidence.latest_imported_at || 'N/A'}`);
    lines.push(`- **Scope Note:** ${dynamicEvidence.scope_note || 'N/A'}`);
    lines.push(`- **High Signal APIs:** ${dynamicEvidence.high_signal_apis.join(', ') || 'none'}`);
    lines.push(`- **Stages:** ${dynamicEvidence.stages.join(', ') || 'none'}`);
    lines.push(`- **Source Formats:** ${(dynamicEvidence.source_formats || []).join(', ') || 'none'}`);
    lines.push(`- **Source Names:** ${(dynamicEvidence.source_names || []).join(', ') || 'none'}`);
    if ((dynamicEvidence.protections || []).length > 0) {
      lines.push(`- **Protections:** ${(dynamicEvidence.protections || []).join(', ')}`);
    }
    if ((dynamicEvidence.address_ranges || []).length > 0) {
      lines.push(`- **Address Ranges:** ${(dynamicEvidence.address_ranges || []).join(', ')}`);
    }
    if ((dynamicEvidence.region_owners || []).length > 0) {
      lines.push(`- **Region Owners:** ${(dynamicEvidence.region_owners || []).join(', ')}`);
    }
    if ((dynamicEvidence.observed_modules || []).length > 0) {
      lines.push(`- **Observed Modules:** ${(dynamicEvidence.observed_modules || []).join(', ')}`);
    }
    if ((dynamicEvidence.segment_names || []).length > 0) {
      lines.push(`- **Segment Names:** ${(dynamicEvidence.segment_names || []).join(', ')}`);
    }

    if ((dynamicEvidence.confidence_layers || []).length > 0) {
      lines.push('');
      lines.push('### Runtime Evidence Lineage');
      lines.push('');
      for (const layer of dynamicEvidence.confidence_layers || []) {
        lines.push(
          `- **${layer.layer}:** artifacts=${layer.artifact_count}, band=${layer.confidence_band}, latest=${layer.latest_imported_at || 'N/A'}, sources=${layer.source_names.join(', ') || 'none'}`
        );
      }
      lines.push('');
    } else {
      lines.push('');
    }
  } else {
    lines.push('- **Artifacts Considered:** 0');
    lines.push('- **Scope Note:** No runtime evidence matched the selected scope.');
    lines.push('');
  }

  if (provenance) {
    lines.push('## Analysis Provenance');
    lines.push('');
    lines.push(`- **Runtime Artifact IDs:** ${provenance.runtime.artifact_ids.join(', ') || 'none'}`);
    lines.push(`- **Runtime Session Tags:** ${provenance.runtime.session_tags.join(', ') || 'none'}`);
    lines.push(`- **Runtime Latest Artifact At:** ${provenance.runtime.latest_artifact_at || 'N/A'}`);
    lines.push(`- **Static Capability Artifact IDs:** ${provenance.static_capabilities.artifact_ids.join(', ') || 'none'}`);
    lines.push(`- **Static Capability Session Tags:** ${provenance.static_capabilities.session_tags.join(', ') || 'none'}`);
    lines.push(`- **PE Structure Artifact IDs:** ${provenance.pe_structure.artifact_ids.join(', ') || 'none'}`);
    lines.push(`- **PE Structure Session Tags:** ${provenance.pe_structure.session_tags.join(', ') || 'none'}`);
    lines.push(`- **Compiler/Packer Artifact IDs:** ${provenance.compiler_packer.artifact_ids.join(', ') || 'none'}`);
    lines.push(`- **Compiler/Packer Session Tags:** ${provenance.compiler_packer.session_tags.join(', ') || 'none'}`);
    lines.push(`- **Semantic Artifact IDs:** ${provenance.semantic_explanations.artifact_ids.join(', ') || 'none'}`);
    lines.push(`- **Semantic Session Tags:** ${provenance.semantic_explanations.session_tags.join(', ') || 'none'}`);
    lines.push(`- **Semantic Latest Artifact At:** ${provenance.semantic_explanations.latest_artifact_at || 'N/A'}`);
    lines.push('');
  }

  if (ghidraExecution) {
    lines.push('## Ghidra Execution');
    lines.push('');
    lines.push(`- **Analysis ID:** ${ghidraExecution.analysis_id}`);
    lines.push(`- **Selected Source:** ${ghidraExecution.selected_source}`);
    lines.push(`- **Status:** ${ghidraExecution.status}`);
    lines.push(`- **Function Count:** ${ghidraExecution.function_count}`);
    lines.push(`- **Project Path:** ${ghidraExecution.project_path || 'N/A'}`);
    lines.push(`- **Project Root:** ${ghidraExecution.project_root || 'N/A'}`);
    lines.push(`- **Log Root:** ${ghidraExecution.log_root || 'N/A'}`);
    lines.push(`- **Command Logs:** ${ghidraExecution.command_log_paths.join(', ') || 'none'}`);
    lines.push(`- **Runtime Logs:** ${ghidraExecution.runtime_log_paths.join(', ') || 'none'}`);
    lines.push(
      `- **Function Extraction:** ${ghidraExecution.function_extraction_status || 'unknown'}${ghidraExecution.function_extraction_script ? ` via ${ghidraExecution.function_extraction_script}` : ''}`
    );
    if (ghidraExecution.java_exception) {
      lines.push(
        `- **Java Exception:** ${ghidraExecution.java_exception.exception_class}: ${ghidraExecution.java_exception.message}`
      );
    }
    if (ghidraExecution.progress_stages.length > 0) {
      lines.push('- **Progress Stages:**');
      for (const stage of ghidraExecution.progress_stages) {
        lines.push(`  - ${stage.progress}% ${stage.stage}${stage.detail ? ` (${stage.detail})` : ''}`);
      }
    }
    lines.push('');
  }

  if (
    selectionDiffs &&
    (
      selectionDiffs.runtime ||
      selectionDiffs.static_capabilities ||
      selectionDiffs.pe_structure ||
      selectionDiffs.compiler_packer ||
      selectionDiffs.semantic_explanations
    )
  ) {
    lines.push('## Selection Diffs');
    lines.push('');
    if (selectionDiffs.runtime) {
      lines.push(`- **Runtime Diff:** ${selectionDiffs.runtime.summary}`);
    }
    if (selectionDiffs.static_capabilities) {
      lines.push(`- **Static Capability Diff:** ${selectionDiffs.static_capabilities.summary}`);
    }
    if (selectionDiffs.pe_structure) {
      lines.push(`- **PE Structure Diff:** ${selectionDiffs.pe_structure.summary}`);
    }
    if (selectionDiffs.compiler_packer) {
      lines.push(`- **Compiler/Packer Diff:** ${selectionDiffs.compiler_packer.summary}`);
    }
    if (selectionDiffs.semantic_explanations) {
      lines.push(`- **Semantic Diff:** ${selectionDiffs.semantic_explanations.summary}`);
    }
    lines.push('');
  }

  if (functionExplanations.length > 0) {
    lines.push('## Function Explanations');
    lines.push('');
    lines.push(`- **Semantic Scope:** ${semanticScope}`);
    lines.push(`- **Semantic Session Selector:** ${semanticSessionTag || 'N/A'}`);
    lines.push('');
    for (const explanation of functionExplanations) {
      lines.push(
        `- **${explanation.behavior}:** ${explanation.summary} (confidence=${explanation.confidence.toFixed(2)}, target=${explanation.function || explanation.address || 'unknown'}, source=${explanation.source || 'unknown'})`
      );
      if (explanation.rewrite_guidance.length > 0) {
        lines.push(`  rewrite_guidance: ${explanation.rewrite_guidance.join(' | ')}`);
      }
    }
    lines.push('');
  }

  const confidenceSemantics = buildReportConfidenceSemantics({
    score: dynamicEvidence?.executed ? 0.72 : dynamicEvidence ? 0.58 : 0.42,
    evidenceScope,
    runtimeLayers:
      dynamicEvidence?.confidence_layers?.map((item) => item.layer) || ['static_only'],
    executedTracePresent: dynamicEvidence?.executed || false,
  });
  lines.push('## Confidence Semantics');
  lines.push('');
  lines.push(`- **Score Kind:** ${confidenceSemantics.score_kind}`);
  lines.push(`- **Band:** ${confidenceSemantics.band}`);
  lines.push(`- **Calibrated Probability:** ${confidenceSemantics.calibrated ? 'Yes' : 'No'}`);
  lines.push(`- **Meaning:** ${confidenceSemantics.meaning}`);
  lines.push(`- **Compare Within:** ${confidenceSemantics.compare_within}`);
  lines.push(`- **Caution:** ${confidenceSemantics.caution}`);
  lines.push(`- **Drivers:** ${confidenceSemantics.drivers.join(', ') || 'none'}`);
  lines.push('');

  // Footer
  lines.push('---');
  lines.push('');
  lines.push('*Report generated by Windows EXE Decompiler MCP Server*');
  lines.push('');

  return lines.join('\n');
}

/**
 * Create handler for report.generate tool
 */
export function createReportGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager?: CacheManager,
  deps?: {
    binaryRoleProfileHandler?: (args: Record<string, unknown>) => Promise<{
      ok: boolean
      data?: unknown
      errors?: string[]
      warnings?: string[]
    }>
    rustBinaryAnalyzeHandler?: (args: Record<string, unknown>) => Promise<{
      ok: boolean
      data?: unknown
      errors?: string[]
      warnings?: string[]
    }>
  }
): ToolHandler {
  const binaryRoleProfileHandler =
    deps?.binaryRoleProfileHandler ||
    (cacheManager ? createBinaryRoleProfileHandler(workspaceManager, database, cacheManager) : undefined)
  const rustBinaryAnalyzeHandler =
    deps?.rustBinaryAnalyzeHandler ||
    (cacheManager ? createRustBinaryAnalyzeHandler(workspaceManager, database, cacheManager) : undefined)

  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = reportGenerateInputSchema.parse(args);

      logger.info({
        sample_id: input.sample_id,
        format: input.format,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag || null,
      }, 'report.generate tool called');

      // Check if sample exists
      const sample = database.findSample(input.sample_id);
      if (!sample) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [`Sample not found: ${input.sample_id}`]
            }, null, 2)
          }],
          isError: true
        };
      }

      // Get all analyses for this sample
      const analyses = database.findAnalysesBySample(input.sample_id);

      // Get all functions for this sample
      const functions = database.findFunctions(input.sample_id);

      const dynamicEvidence = await loadDynamicTraceEvidence(
        workspaceManager,
        database,
        input.sample_id,
        {
          evidenceScope: input.evidence_scope,
          sessionTag: input.evidence_session_tag,
        }
      );
      const functionExplanationIndex = await loadSemanticFunctionExplanationIndex(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: input.semantic_scope,
          sessionTag: input.semantic_session_tag,
        }
      );
      const functionExplanations = Array.from(functionExplanationIndex.byAddress.values())
        .sort((a, b) => {
          if (b.confidence !== a.confidence) {
            return b.confidence - a.confidence;
          }
          return (b.created_at || '').localeCompare(a.created_at || '');
        })
        .slice(0, 6)
        .map((item) => ({
          address: item.address,
          function: item.function,
          behavior: item.behavior,
          summary: item.summary,
          confidence: item.confidence,
          rewrite_guidance: item.rewrite_guidance.slice(0, 4),
          source: item.model_name || item.client_name || null,
        }));
      const [staticCapabilitiesSelection, peStructureSelection, compilerPackerSelection] =
        await Promise.all([
          loadStaticAnalysisArtifactSelection<z.infer<typeof StaticCapabilityTriageDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
            {
              scope: input.static_scope,
              sessionTag: input.static_session_tag,
            }
          ),
          loadStaticAnalysisArtifactSelection<z.infer<typeof PEStructureAnalyzeDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
            {
              scope: input.static_scope,
              sessionTag: input.static_session_tag,
            }
          ),
          loadStaticAnalysisArtifactSelection<z.infer<typeof CompilerPackerDetectDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
            {
              scope: input.static_scope,
              sessionTag: input.static_session_tag,
            }
          ),
        ]);
      const staticCapabilities = staticCapabilitiesSelection.latest_payload;
      const peStructure = peStructureSelection.latest_payload;
      const compilerPacker = compilerPackerSelection.latest_payload;
      let binaryProfile: z.infer<typeof BinaryRoleProfileDataSchema> | null = null;
      let rustProfile: z.infer<typeof RustBinaryAnalyzeDataSchema> | null = null;
      if (binaryRoleProfileHandler) {
        const binaryRoleProfileResult = await binaryRoleProfileHandler({
          sample_id: input.sample_id,
        });
        if (binaryRoleProfileResult.ok && binaryRoleProfileResult.data) {
          binaryProfile = binaryRoleProfileResult.data as z.infer<typeof BinaryRoleProfileDataSchema>;
        }
      }
      if (rustBinaryAnalyzeHandler) {
        const rustBinaryAnalyzeResult = await rustBinaryAnalyzeHandler({
          sample_id: input.sample_id,
        });
        if (rustBinaryAnalyzeResult.ok && rustBinaryAnalyzeResult.data) {
          rustProfile = rustBinaryAnalyzeResult.data as z.infer<typeof RustBinaryAnalyzeDataSchema>;
        }
      }
      const provenance = {
        runtime: buildRuntimeArtifactProvenance(
          dynamicEvidence,
          input.evidence_scope,
          input.evidence_session_tag
        ),
        static_capabilities: buildStaticArtifactProvenance(
          'static capability artifacts',
          staticCapabilitiesSelection,
          input.static_scope,
          input.static_session_tag
        ),
        pe_structure: buildStaticArtifactProvenance(
          'pe structure artifacts',
          peStructureSelection,
          input.static_scope,
          input.static_session_tag
        ),
        compiler_packer: buildStaticArtifactProvenance(
          'compiler/packer attribution artifacts',
          compilerPackerSelection,
          input.static_scope,
          input.static_session_tag
        ),
        semantic_explanations: buildSemanticArtifactProvenance(
          'semantic explanation artifacts',
          functionExplanationIndex,
          input.semantic_scope,
          input.semantic_session_tag
        ),
      };
      const ghidraExecution = buildGhidraExecutionSummary(analyses);
      const selectionDiffs: {
        runtime?: ReturnType<typeof buildArtifactSelectionDiff>;
        static_capabilities?: ReturnType<typeof buildArtifactSelectionDiff>;
        pe_structure?: ReturnType<typeof buildArtifactSelectionDiff>;
        compiler_packer?: ReturnType<typeof buildArtifactSelectionDiff>;
        semantic_explanations?: ReturnType<typeof buildArtifactSelectionDiff>;
      } = {};
      if (input.compare_evidence_scope) {
        const baselineDynamicEvidence = await loadDynamicTraceEvidence(
          workspaceManager,
          database,
          input.sample_id,
          {
            evidenceScope: input.compare_evidence_scope,
            sessionTag: input.compare_evidence_session_tag,
          }
        );
        selectionDiffs.runtime = buildArtifactSelectionDiff(
          'runtime',
          provenance.runtime,
          buildRuntimeArtifactProvenance(
            baselineDynamicEvidence,
            input.compare_evidence_scope,
            input.compare_evidence_session_tag
          )
        );
      }
      if (input.compare_static_scope) {
        const [baselineCapabilities, baselinePeStructure, baselineCompilerPacker] = await Promise.all([
          loadStaticAnalysisArtifactSelection<z.infer<typeof StaticCapabilityTriageDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
            {
              scope: input.compare_static_scope,
              sessionTag: input.compare_static_session_tag,
            }
          ),
          loadStaticAnalysisArtifactSelection<z.infer<typeof PEStructureAnalyzeDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE,
            {
              scope: input.compare_static_scope,
              sessionTag: input.compare_static_session_tag,
            }
          ),
          loadStaticAnalysisArtifactSelection<z.infer<typeof CompilerPackerDetectDataSchema>>(
            workspaceManager,
            database,
            input.sample_id,
            COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
            {
              scope: input.compare_static_scope,
              sessionTag: input.compare_static_session_tag,
            }
          ),
        ]);
        selectionDiffs.static_capabilities = buildArtifactSelectionDiff(
          'static_capabilities',
          provenance.static_capabilities,
          buildStaticArtifactProvenance(
            'static capability artifacts',
            baselineCapabilities,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        );
        selectionDiffs.pe_structure = buildArtifactSelectionDiff(
          'pe_structure',
          provenance.pe_structure,
          buildStaticArtifactProvenance(
            'pe structure artifacts',
            baselinePeStructure,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        );
        selectionDiffs.compiler_packer = buildArtifactSelectionDiff(
          'compiler_packer',
          provenance.compiler_packer,
          buildStaticArtifactProvenance(
            'compiler/packer attribution artifacts',
            baselineCompilerPacker,
            input.compare_static_scope,
            input.compare_static_session_tag
          )
        );
      }
      if (input.compare_semantic_scope) {
        const baselineSemanticIndex = await loadSemanticFunctionExplanationIndex(
          workspaceManager,
          database,
          input.sample_id,
          {
            scope: input.compare_semantic_scope,
            sessionTag: input.compare_semantic_session_tag,
          }
        );
        selectionDiffs.semantic_explanations = buildArtifactSelectionDiff(
          'semantic_explanations',
          provenance.semantic_explanations,
          buildSemanticArtifactProvenance(
            'semantic explanation artifacts',
            baselineSemanticIndex,
            input.compare_semantic_scope,
            input.compare_semantic_session_tag
          )
        );
      }

      // Generate report based on format
      const format = input.format || 'markdown';
      let reportContent: string;
      let reportExtension: string;
      let mimeType: string;

      switch (format) {
        case 'markdown':
          reportContent = generateMarkdownReport(
            sample,
            analyses,
            functions,
            dynamicEvidence,
            binaryProfile,
            rustProfile,
            staticCapabilities,
            peStructure,
            compilerPacker,
            functionExplanations,
            input.evidence_scope,
            input.evidence_session_tag,
            input.static_scope,
            input.static_session_tag,
            input.semantic_scope,
            input.semantic_session_tag,
            provenance,
            ghidraExecution,
            selectionDiffs
          );
          reportExtension = 'md';
          mimeType = 'text/markdown';
          break;

        case 'json':
          const confidenceSemantics = buildReportConfidenceSemantics({
            score: dynamicEvidence?.executed ? 0.72 : dynamicEvidence ? 0.58 : 0.42,
            evidenceScope: input.evidence_scope,
            runtimeLayers:
              dynamicEvidence?.confidence_layers?.map((item) => item.layer) || ['static_only'],
            executedTracePresent: dynamicEvidence?.executed || false,
          });
          reportContent = JSON.stringify({
            sample,
            analyses,
            functions,
            dynamic_evidence: dynamicEvidence,
            binary_profile: binaryProfile,
            rust_profile: rustProfile,
            static_capabilities: staticCapabilities,
            pe_structure: peStructure,
            compiler_packer: compilerPacker,
            function_explanations: functionExplanations,
            evidence_scope: input.evidence_scope,
            evidence_session_tag: input.evidence_session_tag || null,
            static_scope: input.static_scope,
            static_session_tag: input.static_session_tag || null,
            semantic_scope: input.semantic_scope,
            semantic_session_tag: input.semantic_session_tag || null,
            provenance,
            ghidra_execution: ghidraExecution,
            selection_diffs: Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined,
            confidence_semantics: confidenceSemantics,
            generated_at: new Date().toISOString()
          }, null, 2);
          reportExtension = 'json';
          mimeType = 'application/json';
          break;

        case 'html':
          // Simple HTML wrapper around markdown
          reportContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Analysis Report: ${sample.sha256}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
  </style>
</head>
<body>
<pre>${generateMarkdownReport(
  sample,
  analyses,
  functions,
  dynamicEvidence,
  binaryProfile,
  rustProfile,
  staticCapabilities,
  peStructure,
  compilerPacker,
  functionExplanations,
  input.evidence_scope,
  input.evidence_session_tag,
  input.static_scope,
  input.static_session_tag,
  input.semantic_scope,
  input.semantic_session_tag,
  provenance,
  ghidraExecution,
  selectionDiffs
)}</pre>
</body>
</html>`;
          reportExtension = 'html';
          mimeType = 'text/html';
          break;

        default:
          throw new Error(`Unsupported format: ${format}`);
      }

      // Store report to workspace
      const workspace = await workspaceManager.getWorkspace(input.sample_id);
      const reportFilename = `report_${Date.now()}.${reportExtension}`;
      const reportPath = path.join(workspace.reports, reportFilename);

      // Ensure reports directory exists
      if (!fs.existsSync(workspace.reports)) {
        fs.mkdirSync(workspace.reports, { recursive: true });
      }

      // Write report file
      fs.writeFileSync(reportPath, reportContent, 'utf-8');

      // Compute SHA256 of report
      const reportSha256 = createHash('sha256')
        .update(reportContent)
        .digest('hex');

      // Insert artifact record
      const artifactId = randomUUID();
      database.insertArtifact({
        id: artifactId,
        sample_id: input.sample_id,
        type: `report_${format}`,
        path: `reports/${reportFilename}`,
        sha256: reportSha256,
        mime: mimeType,
        created_at: new Date().toISOString()
      });

      logger.info({
        sample_id: input.sample_id,
        format,
        artifact_id: artifactId,
        path: reportPath
      }, 'Report generated successfully');

      return {
        structuredContent: {
          ok: true,
          data: {
            artifact_id: artifactId,
            path: reportPath,
            format,
            size: reportContent.length,
            sha256: reportSha256,
            tool_surface_role: 'export_only',
            preferred_primary_tools: ['workflow.summarize', 'report.summarize'],
            recommended_next_tools: ['artifact.read', 'workflow.summarize', 'report.summarize'],
            next_actions: [
              'Use workflow.summarize for the primary staged analyst-facing synthesis flow.',
              'Use report.summarize when you want a deterministic compact compatibility digest instead of a report export.',
              'Use artifact.read on the generated report artifact when you need the full exported document content.',
            ],
            explanation_artifact_refs: database
              .findArtifacts(input.sample_id)
              .filter((item) => item.type === 'analysis_explanation_graph')
              .slice(0, 6)
              .map((item) => ({
                id: item.id,
                type: item.type,
                path: item.path,
                sha256: item.sha256,
                ...(item.mime ? { mime: item.mime } : {}),
              })),
            provenance,
            ghidra_execution: ghidraExecution,
            selection_diffs: Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined
          }
        },
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: {
              artifact_id: artifactId,
              path: reportPath,
              format,
              size: reportContent.length,
              sha256: reportSha256,
              tool_surface_role: 'export_only',
              preferred_primary_tools: ['workflow.summarize', 'report.summarize'],
              recommended_next_tools: ['artifact.read', 'workflow.summarize', 'report.summarize'],
              next_actions: [
                'Use workflow.summarize for the primary staged analyst-facing synthesis flow.',
                'Use report.summarize when you want a deterministic compact compatibility digest instead of a report export.',
                'Use artifact.read on the generated report artifact when you need the full exported document content.',
              ],
              explanation_artifact_refs: database
                .findArtifacts(input.sample_id)
                .filter((item) => item.type === 'analysis_explanation_graph')
                .slice(0, 6)
                .map((item) => ({
                  id: item.id,
                  type: item.type,
                  path: item.path,
                  sha256: item.sha256,
                  ...(item.mime ? { mime: item.mime } : {}),
                })),
              provenance,
              ghidra_execution: ghidraExecution,
              selection_diffs: Object.keys(selectionDiffs).length > 0 ? selectionDiffs : undefined
            }
          }, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage
      }, 'report.generate tool failed');

      return {
        structuredContent: {
          ok: false,
          errors: [errorMessage]
        },
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: false,
            errors: [errorMessage]
          }, null, 2)
        }],
        isError: true
      };
    }
  };
}
