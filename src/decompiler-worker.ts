/**
 * Decompiler Worker - Ghidra Headless integration
 * 
 * Implements requirements 8.1-8.6:
 * - Creates isolated Ghidra project spaces
 * - Executes Ghidra Headless analysis
 * - Extracts function lists
 * - Stores results in database
 * - Handles timeouts and failures
 */

import { spawn, type ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import { createHash, randomUUID } from 'crypto';
import { logger } from './logger.js';
import {
  ghidraConfig,
  createGhidraProject,
  buildProcessInvocation,
  type ProcessInvocation,
  getConfiguredGhidraLogRoot,
  getConfiguredGhidraProjectRoot,
  getSampleScopedGhidraProjectRoot,
} from './ghidra-config.js';
import {
  findBestGhidraAnalysis,
  getGhidraCapabilityStatus,
  isGhidraCapabilityReady,
  parseGhidraAnalysisMetadata,
  type GhidraCapability,
  type GhidraCapabilityStatus,
} from './ghidra-analysis-status.js';
import {
  buildRawCommandLine,
  decodeProcessStreams,
  type DecodedProcessStreams,
} from './process-output.js';
import { smartRecoverFunctionsFromPE, type SmartRecoveredFunction } from './pe-runtime-functions.js';
import type { DatabaseManager, Analysis } from './database.js';
import type { WorkspaceManager } from './workspace-manager.js';
import type { JobResult } from './types.js';
import { formatMissingOriginalError, resolvePrimarySamplePath } from './sample-workspace.js';

/**
 * Options for Ghidra analysis
 * Requirements: 8.1
 */
export interface GhidraOptions {
  analysisId?: string;
  projectKey?: string;
  analysisOptions?: Record<string, unknown>;
  timeout?: number;
  maxCpu?: string;
  processor?: string;
  languageId?: string;
  cspec?: string;
  scriptPaths?: string[];
  abortSignal?: AbortSignal;
  onProgress?: (progress: number, stage: string, detail?: string) => void;
}

/**
 * Result of Ghidra analysis
 * Requirements: 8.2, 8.3, 8.4
 */
export interface AnalysisResult {
  analysisId: string;
  backend: 'ghidra';
  functionCount: number;
  projectPath: string;
  status: 'done' | 'partial_success';
  warnings?: string[];
  readiness?: {
    function_index: GhidraCapabilityStatus;
    decompile: GhidraCapabilityStatus;
    cfg: GhidraCapabilityStatus;
  };
}

/**
 * Function information extracted from Ghidra
 * Requirements: 8.3
 */
export interface GhidraFunction {
  address: string;
  name: string;
  size: number;
  is_thunk: boolean;
  is_external: boolean;
  calling_convention: string;
  signature: string;
  callers: Array<{ address: string; name: string }>;
  caller_count: number;
  callees: Array<{ address: string; name: string }>;
  callee_count: number;
  caller_relationships?: FunctionRelationship[];
  callee_relationships?: FunctionRelationship[];
  is_entry_point: boolean;
  is_exported: boolean;
}

/**
 * Ghidra analysis output format
 */
export interface GhidraAnalysisOutput {
  program_name: string;
  program_path: string;
  function_count: number;
  functions: GhidraFunction[];
}

/**
 * Function information for listing
 * Requirements: 9.1
 */
export interface FunctionInfo {
  name: string;
  address: string;
  size: number;
  callers: number;
  callees: number;
}

/**
 * Ranked function with score and reasons
 * Requirements: 9.2, 9.8
 */
export interface RankedFunction {
  address: string;
  name: string;
  score: number;
  reasons: string[];
  xref_summary?: FunctionXrefSummary[];
}

export interface FunctionXrefSummary {
  api: string;
  provenance:
    | 'static_named_call'
    | 'dynamic_resolution_api'
    | 'dynamic_resolution_helper'
    | 'global_string_hint'
    | 'unknown';
  confidence: number;
  evidence: string[];
}

export interface FunctionRelationship {
  address: string;
  name: string;
  relation_types: string[];
  reference_types: string[];
  reference_addresses: string[];
  target_addresses?: string[];
  resolved_by?: string;
  is_exact?: boolean;
}

export interface FunctionSearchStringMatch {
  value: string;
  data_address?: string;
  referenced_from?: string;
}

export interface FunctionSearchMatch {
  function: string;
  address: string;
  caller_count: number;
  callee_count: number;
  api_matches?: string[];
  string_matches?: FunctionSearchStringMatch[];
  match_types: Array<'api_call' | 'string_reference' | 'api_call_index'>;
}

export interface FunctionSearchResult {
  query: {
    api?: string;
    string?: string;
    limit: number;
  };
  matches: FunctionSearchMatch[];
  count: number;
}

/**
 * Cross-reference information
 * Requirements: 10.4
 */
export interface CrossReference {
  from_address: string;
  type: string;
  is_call: boolean;
  is_data: boolean;
  from_function?: string;
}

export interface CrossReferenceTarget {
  query: string;
  resolved_address?: string;
  resolved_name?: string;
}

export interface CrossReferenceNode {
  function: string;
  address: string;
  depth: number;
  relation: string;
  reference_types: string[];
  reference_addresses: string[];
  matched_values: string[];
}

export interface CrossReferenceAnalysis {
  target_type: 'function' | 'api' | 'string' | 'data';
  target: CrossReferenceTarget;
  inbound: CrossReferenceNode[];
  outbound: CrossReferenceNode[];
  direct_xrefs: CrossReference[];
  truncated: boolean;
  limits: {
    depth: number;
    limit: number;
  };
}

/**
 * Decompiled function result
 * Requirements: 10.1, 10.2, 10.3, 10.4
 */
export interface DecompiledFunction {
  function: string;
  address: string;
  pseudocode: string;
  callers: Array<{ address: string; name: string }>;
  callees: Array<{ address: string; name: string }>;
  caller_relationships?: FunctionRelationship[];
  callee_relationships?: FunctionRelationship[];
  xrefs?: CrossReference[];
}

/**
 * CFG Node
 * Requirements: 11.2, 11.3
 */
export interface CFGNode {
  id: string;
  address: string;
  instructions: string[];
  type: 'entry' | 'exit' | 'basic' | 'call' | 'return';
}

/**
 * CFG Edge
 * Requirements: 11.4
 */
export interface CFGEdge {
  from: string;
  to: string;
  type: 'fallthrough' | 'jump' | 'call' | 'return';
}

/**
 * Control Flow Graph
 * Requirements: 11.1, 11.5
 */
export interface ControlFlowGraph {
  function: string;
  address: string;
  nodes: CFGNode[];
  edges: CFGEdge[];
}

export interface GhidraProcessDiagnostics {
  raw_cmd: string;
  command: string;
  args: string[];
  cwd: string;
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  timed_out: boolean;
  cancelled: boolean;
  stdout: string;
  stderr: string;
  stdout_encoding: string;
  stderr_encoding: string;
  spawn_error?: string;
  log_path?: string;
  runtime_log_path?: string;
  java_exception?: {
    exception_class: string;
    message: string;
    stack_preview: string[];
  };
}

export interface NormalizedGhidraError {
  code:
    | 'timeout'
    | 'cancelled'
    | 'project_lock'
    | 'project_directory_missing'
    | 'java_runtime_invalid'
    | 'spawn_einval'
    | 'spawn_failure'
    | 'pyghidra_unavailable'
    | 'script_runtime_require_undefined'
    | 'missing_json_output'
    | 'ghidra_process_failure'
    | 'unknown'
  category: 'transient' | 'environment' | 'configuration' | 'script_output' | 'process' | 'user'
  summary: string
  remediation_hints: string[]
  evidence: string[]
  stage?: string
}

interface GhidraCommandOutput {
  stdout: string;
  stderr: string;
  diagnostics: GhidraProcessDiagnostics;
  command_log_path?: string;
  runtime_log_path?: string;
}

interface FunctionExtractionAttempt {
  script: string;
  stdout?: string;
  stderr?: string;
  diagnostics?: GhidraProcessDiagnostics;
  command_log_path?: string;
  runtime_log_path?: string;
  parse_error?: string;
  error?: string;
}

interface FunctionExtractionResult {
  output?: GhidraAnalysisOutput;
  warnings: string[];
  scriptUsed?: string;
  attempts: FunctionExtractionAttempt[];
}

interface FunctionRecoveryResult {
  functions: GhidraFunction[];
  warnings: string[];
  recoveryMetadata?: Record<string, unknown>;
}

interface GhidraCapabilityProbeResult {
  status: GhidraCapabilityStatus;
  output?: GhidraCommandOutput;
}

interface ParsedGhidraError {
  error: string;
  diagnostics?: GhidraProcessDiagnostics;
}

export class GhidraProcessError extends Error {
  public readonly errorCode: 'E_TIMEOUT' | 'E_SPAWN' | 'E_GHIDRA_PROCESS' | 'E_CANCELLED';
  public readonly diagnostics: GhidraProcessDiagnostics;

  constructor(
    message: string,
    diagnostics: GhidraProcessDiagnostics,
    errorCode: 'E_TIMEOUT' | 'E_SPAWN' | 'E_GHIDRA_PROCESS' | 'E_CANCELLED'
  ) {
    super(message);
    this.name = 'GhidraProcessError';
    this.errorCode = errorCode;
    this.diagnostics = diagnostics;
  }
}

export class GhidraOutputParseError extends Error {
  public readonly diagnostics: GhidraProcessDiagnostics;

  constructor(message: string, diagnostics: GhidraProcessDiagnostics) {
    super(message);
    this.name = 'GhidraOutputParseError';
    this.diagnostics = diagnostics;
  }
}

export function getGhidraDiagnostics(error: unknown): GhidraProcessDiagnostics | undefined {
  if (error instanceof GhidraProcessError || error instanceof GhidraOutputParseError) {
    return error.diagnostics;
  }
  return undefined;
}

function truncateDiagnosticText(value: string | undefined, limit: number = 240): string | null {
  if (!value) {
    return null
  }
  const normalized = value.replace(/\0/g, '').trim()
  if (normalized.length === 0) {
    return null
  }
  if (normalized.length <= limit) {
    return normalized
  }
  return `${normalized.slice(0, limit)}...`
}

function parseJavaExceptionSummary(text: string | undefined): {
  exception_class: string
  message: string
  stack_preview: string[]
} | undefined {
  if (!text) {
    return undefined
  }

  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)

  const firstExceptionIndex = lines.findIndex((line) =>
    /(?:^|[\s:])(java|javax|ghidra)\.[A-Za-z0-9_.$]+(?:Exception|Error)\b/.test(line)
  )

  if (firstExceptionIndex < 0) {
    return undefined
  }

  const exceptionLine = lines[firstExceptionIndex]
  const match = exceptionLine.match(/((?:java|javax|ghidra)\.[A-Za-z0-9_.$]+(?:Exception|Error))(?::\s*(.*))?/)
  if (!match) {
    return undefined
  }

  const stack_preview = lines
    .slice(firstExceptionIndex + 1)
    .filter((line) => /^at\s+/.test(line))
    .slice(0, 4)

  return {
    exception_class: match[1],
    message: (match[2] || exceptionLine).trim(),
    stack_preview,
  }
}

export function normalizeGhidraError(
  error: unknown,
  stage?: string
): NormalizedGhidraError | undefined {
  const diagnostics = getGhidraDiagnostics(error)
  const message = error instanceof Error ? error.message : String(error)
  const corpus = [message, diagnostics?.stderr, diagnostics?.stdout, diagnostics?.spawn_error]
    .filter((item): item is string => typeof item === 'string' && item.length > 0)
    .join('\n')

  if (!message && !diagnostics) {
    return undefined
  }

  const evidence = [
    diagnostics?.raw_cmd ? `raw_cmd=${diagnostics.raw_cmd}` : '',
    typeof diagnostics?.exit_code === 'number' ? `exit_code=${diagnostics.exit_code}` : '',
    diagnostics?.spawn_error ? `spawn_error=${diagnostics.spawn_error}` : '',
    diagnostics?.log_path ? `log_path=${diagnostics.log_path}` : '',
    diagnostics?.runtime_log_path ? `runtime_log_path=${diagnostics.runtime_log_path}` : '',
    diagnostics?.java_exception
      ? `java_exception=${diagnostics.java_exception.exception_class}: ${diagnostics.java_exception.message}`
      : '',
    truncateDiagnosticText(diagnostics?.stderr) ? `stderr=${truncateDiagnosticText(diagnostics?.stderr)}` : '',
    truncateDiagnosticText(diagnostics?.stdout) ? `stdout=${truncateDiagnosticText(diagnostics?.stdout)}` : '',
  ].filter((item): item is string => item.length > 0)

  const withStage = (summary: string): string =>
    stage ? `${stage}: ${summary}` : summary

  if (diagnostics?.cancelled || /E_CANCELLED/i.test(corpus)) {
    return {
      code: 'cancelled',
      category: 'user',
      stage,
      summary: withStage('Ghidra task was cancelled before completion.'),
      remediation_hints: [
        'Re-run the tool if cancellation was accidental.',
        'Use task.status to confirm whether a queued or running job was cancelled.',
      ],
      evidence,
    }
  }

  if (diagnostics?.timed_out || /E_TIMEOUT|timed?\s*out/i.test(corpus)) {
    return {
      code: 'timeout',
      category: 'transient',
      stage,
      summary: withStage('Ghidra execution timed out before producing a complete result.'),
      remediation_hints: [
        'Increase the timeout for the current tool or queued job.',
        'Retry after reducing topk/include_xrefs/include_cfg scope if the sample is large.',
      ],
      evidence,
    }
  }

  if (/unable to lock project|lockexception/i.test(corpus)) {
    return {
      code: 'project_lock',
      category: 'transient',
      stage,
      summary: withStage('Ghidra project lock prevented the script from acquiring the project workspace.'),
      remediation_hints: [
        'Wait for the other Ghidra process to release the project lock, then retry.',
        'Avoid running multiple decompile/CFG/export operations against the same project concurrently.',
      ],
      evidence,
    }
  }

  if (/Directory not found:|FileNotFoundException: Directory not found|DefaultProjectManager\.createProject/i.test(corpus)) {
    return {
      code: 'project_directory_missing',
      category: 'configuration',
      stage,
      summary: withStage('Ghidra could not create or open the project because the project directory is missing or invalid.'),
      remediation_hints: [
        'Set a writable Ghidra project root and ensure its parent directory exists.',
        'If you are overriding the project location, create the parent directory first or let the server create it automatically.',
        'Inspect the attached log_path, runtime_log_path, or java_exception details for the failing project directory.',
      ],
      evidence,
    }
  }

  if (/JAVA_HOME|UnsupportedClassVersionError|class file version|JavaRuntime|java version/i.test(corpus)) {
    return {
      code: 'java_runtime_invalid',
      category: 'environment',
      stage,
      summary: withStage('Ghidra launch appears to be blocked by a missing or incompatible Java runtime.'),
      remediation_hints: [
        'Set JAVA_HOME to a Java 21+ installation and retry.',
        'Run system.setup.guide or ghidra.health to retrieve explicit Java and Ghidra setup actions.',
      ],
      evidence,
    }
  }

  if (/spawn.*EINVAL/i.test(corpus) || /EINVAL/i.test(diagnostics?.spawn_error || '')) {
    return {
      code: 'spawn_einval',
      category: 'configuration',
      stage,
      summary: withStage('Ghidra process could not be spawned due to Windows batch/script invocation mismatch (EINVAL).'),
      remediation_hints: [
        'Ensure GHIDRA_PATH/GHIDRA_INSTALL_DIR points to a valid Ghidra installation root.',
        'Prefer launching analyzeHeadless through the configured batch-wrapper path instead of hand-crafted shell quoting.',
        'Avoid broken quoting or partially expanded PATH entries when Ghidra lives under a path with spaces.',
      ],
      evidence,
    }
  }

  if (/Ghidra was not started with PyGhidra|Python is not available/i.test(corpus)) {
    return {
      code: 'pyghidra_unavailable',
      category: 'environment',
      stage,
      summary: withStage('PyGhidra is unavailable in the active environment, so Python post-scripts cannot run.'),
      remediation_hints: [
        'Use the Java post-script fallback if available.',
        'Install/configure the Python environment bundled for PyGhidra if Python post-scripts are required.',
      ],
      evidence,
    }
  }

  if (/require is not defined/i.test(corpus)) {
    return {
      code: 'script_runtime_require_undefined',
      category: 'script_output',
      stage,
      summary: withStage('The Ghidra-side script used a runtime that does not support require().'),
      remediation_hints: [
        'Do not use Node-style require() inside Ghidra post-scripts.',
        'Port the script to Java/Ghidra APIs or bundle dependencies explicitly for the target runtime.',
      ],
      evidence,
    }
  }

  if (/No JSON output found/i.test(corpus)) {
    return {
      code: 'missing_json_output',
      category: 'script_output',
      stage,
      summary: withStage('The Ghidra script exited without emitting the expected JSON payload.'),
      remediation_hints: [
        'Inspect stderr/stdout snippets to see whether the post-script crashed before printing JSON.',
        'Check for project-lock, PyGhidra, or script-runtime errors in the attached diagnostics.',
      ],
      evidence,
    }
  }

  if (diagnostics?.spawn_error || error instanceof GhidraProcessError && error.errorCode === 'E_SPAWN') {
    return {
      code: 'spawn_failure',
      category: 'environment',
      stage,
      summary: withStage('The Ghidra process failed to start.'),
      remediation_hints: [
        'Verify the configured analyzeHeadless executable exists and is executable.',
        'Check PATH/GHIDRA_PATH/GHIDRA_INSTALL_DIR and Windows shell quoting for the current installation path.',
      ],
      evidence,
    }
  }

  if (diagnostics && diagnostics.exit_code !== null && diagnostics.exit_code !== 0) {
    return {
      code: 'ghidra_process_failure',
      category: 'process',
      stage,
      summary: withStage('Ghidra exited with a non-zero status.'),
      remediation_hints: [
        'Inspect stderr and raw_cmd to identify the failing post-script or analyzeHeadless phase.',
        'Retry with ghidra.health or a narrower tool scope if the failure is isolated to one capability.',
      ],
      evidence,
    }
  }

  return {
    code: 'unknown',
    category: 'process',
    stage,
    summary: withStage('Ghidra reported an unclassified failure.'),
    remediation_hints: [
      'Inspect the attached diagnostics and retry with ghidra.health for an end-to-end probe.',
    ],
    evidence,
  }
}

/**
 * Decompiler Worker class
 * Manages Ghidra Headless execution and result processing
 */
export class DecompilerWorker {
  constructor(
    private database: DatabaseManager,
    private workspaceManager: WorkspaceManager
  ) {}

  private async delay(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  private isProjectLockFailure(error: unknown): boolean {
    const diagnostics = getGhidraDiagnostics(error);
    const corpus = [
      error instanceof Error ? error.message : String(error),
      diagnostics?.stdout,
      diagnostics?.stderr,
      diagnostics?.spawn_error,
    ]
      .filter((value): value is string => typeof value === 'string' && value.length > 0)
      .join('\n');

    return /unable to lock project|lockexception/i.test(corpus);
  }

  private async runWithProjectLockRetry<T>(
    operationLabel: string,
    operation: () => Promise<T>,
    context: Record<string, unknown>,
    attempts: number = 5,
    initialDelayMs: number = 1500
  ): Promise<T> {
    let delayMs = initialDelayMs;
    let lastError: unknown;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        if (!this.isProjectLockFailure(error) || attempt >= attempts) {
          throw error;
        }

        logger.warn(
          {
            ...context,
            attempt,
            attempts,
            retry_delay_ms: delayMs,
            error: error instanceof Error ? error.message : String(error),
          },
          `${operationLabel} hit a transient Ghidra project lock; retrying`
        );

        await this.delay(delayMs);
        delayMs *= 2;
      }
    }

    throw lastError instanceof Error ? lastError : new Error(`${operationLabel} failed`);
  }

  private async resolveSamplePathForSample(sampleId: string): Promise<string> {
    const { samplePath, integrity } = await resolvePrimarySamplePath(this.workspaceManager, sampleId);
    if (!samplePath) {
      throw new Error(formatMissingOriginalError(sampleId, integrity));
    }
    return samplePath;
  }

  private reportProgress(options: GhidraOptions | undefined, progress: number, stage: string, detail?: string): void {
    try {
      options?.onProgress?.(Math.max(0, Math.min(100, progress)), stage, detail)
    } catch (error) {
      logger.warn(
        {
          progress,
          stage,
          detail,
          error: error instanceof Error ? error.message : String(error),
        },
        'Ghidra progress callback failed'
      )
    }
  }

  private buildGhidraCommandLogPath(sampleId: string, stage: string, projectKey?: string): string {
    const sha256 = sampleId.startsWith('sha256:') ? sampleId.slice('sha256:'.length) : sampleId
    const bucket1 = sha256.slice(0, 2)
    const bucket2 = sha256.slice(2, 4)
    const stageKey = stage.replace(/[^a-z0-9._-]+/gi, '_')
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const filename = `${timestamp}_${stageKey}${projectKey ? `_${projectKey}` : ''}.command.log`
    return path.join(ghidraConfig.logRoot, bucket1, bucket2, sha256, filename)
  }

  private buildGhidraRuntimeLogPath(sampleId: string, stage: string, projectKey?: string): string {
    return this.buildGhidraCommandLogPath(sampleId, stage, projectKey).replace(/\.command\.log$/i, '.ghidra.log')
  }

  private persistGhidraCommandLog(
    logFilePath: string | undefined,
    invocation: ProcessInvocation,
    cwd: string,
    decoded: DecodedProcessStreams,
    exitCode: number | null,
    signal: NodeJS.Signals | null,
    timedOut: boolean,
    cancelled: boolean,
    spawnError?: string
  ): string | undefined {
    if (!logFilePath) {
      return undefined
    }

    const payload = [
      `timestamp=${new Date().toISOString()}`,
      `raw_cmd=${buildRawCommandLine(invocation.command, invocation.args)}`,
      `cwd=${cwd}`,
      `exit_code=${exitCode === null ? 'null' : String(exitCode)}`,
      `signal=${signal || 'null'}`,
      `timed_out=${timedOut}`,
      `cancelled=${cancelled}`,
      spawnError ? `spawn_error=${spawnError}` : '',
      '',
      '--- stdout ---',
      decoded.stdout.text,
      '',
      '--- stderr ---',
      decoded.stderr.text,
      '',
    ]
      .filter((line) => line !== '')
      .join('\n')

    fs.mkdirSync(path.dirname(logFilePath), { recursive: true })
    fs.writeFileSync(logFilePath, `${payload}\n`, 'utf8')
    return logFilePath
  }

  private getAlternateWorkspaceRoot(): string | null {
    const currentRoot = this.workspaceManager.getWorkspaceRoot();
    const siblingRoot = path.join(path.dirname(path.dirname(currentRoot)), 'workspaces');
    if (path.resolve(siblingRoot) === path.resolve(currentRoot)) {
      return null;
    }
    return fs.existsSync(siblingRoot) ? siblingRoot : null;
  }

  private findLatestProjectInGhidraDir(ghidraDir: string): { projectPath: string; projectKey: string } | null {
    if (!fs.existsSync(ghidraDir)) {
      return null;
    }

    const candidates = fs
      .readdirSync(ghidraDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name.startsWith('project_'))
      .map((entry) => {
        const projectPath = path.join(ghidraDir, entry.name);
        const projectKey = entry.name.slice('project_'.length);
        const gprPath = path.join(projectPath, `${projectKey}.gpr`);
        const stats = fs.statSync(projectPath);
        return {
          projectPath,
          projectKey,
          gprPath,
          mtimeMs: stats.mtimeMs,
        };
      })
      .filter((item) => fs.existsSync(item.gprPath))
      .sort((left, right) => right.mtimeMs - left.mtimeMs);

    if (candidates.length === 0) {
      return null;
    }

    return {
      projectPath: candidates[0].projectPath,
      projectKey: candidates[0].projectKey,
    };
  }

  private findRecoveredProject(sampleId: string, originalProjectPath: string): { projectPath: string; projectKey: string } | null {
    const sha256 = sampleId.startsWith('sha256:') ? sampleId.slice('sha256:'.length) : sampleId;
    const bucket1 = sha256.slice(0, 2);
    const bucket2 = sha256.slice(2, 4);
    const projectDirName = path.basename(originalProjectPath);
    const currentRoot = this.workspaceManager.getWorkspaceRoot();
    const configuredProjectRoot = getSampleScopedGhidraProjectRoot(sampleId);
    const roots = [configuredProjectRoot, currentRoot, this.getAlternateWorkspaceRoot()].filter(
      (value): value is string => Boolean(value)
    );

    for (const root of roots) {
      const ghidraDir =
        path.resolve(root) === path.resolve(configuredProjectRoot)
          ? root
          : path.join(root, bucket1, bucket2, sha256, 'ghidra');
      const mappedProjectPath = path.join(ghidraDir, projectDirName);
      if (fs.existsSync(mappedProjectPath)) {
        const projectKey = projectDirName.startsWith('project_')
          ? projectDirName.slice('project_'.length)
          : projectDirName;
        return {
          projectPath: mappedProjectPath,
          projectKey,
        };
      }

      const latestProject = this.findLatestProjectInGhidraDir(ghidraDir);
      if (latestProject) {
        return latestProject;
      }
    }

    return null;
  }

  /**
   * Spawn Ghidra process with Windows batch-script compatibility.
   * On Windows, spawning .bat/.cmd directly can throw EINVAL; route through
   * buildProcessInvocation() so batch scripts run via explicit cmd.exe quoting.
   */
  private spawnGhidraProcess(
    invocation: ProcessInvocation,
    cwd: string
  ): ChildProcess {
    return spawn(invocation.command, invocation.args, {
      cwd,
      env: {
        ...process.env,
      },
      windowsHide: true,
      windowsVerbatimArguments: invocation.windowsVerbatimArguments === true,
    });
  }

  private buildProcessDiagnostics(
    invocation: ProcessInvocation,
    cwd: string,
    decoded: DecodedProcessStreams,
    exitCode: number | null,
    signal: NodeJS.Signals | null,
    timedOut: boolean,
    cancelled: boolean,
    spawnError?: string,
    logPath?: string,
    runtimeLogPath?: string
  ): GhidraProcessDiagnostics {
    const javaException = parseJavaExceptionSummary(`${decoded.stderr.text}\n${decoded.stdout.text}`);
    return {
      raw_cmd: buildRawCommandLine(invocation.command, invocation.args),
      command: invocation.command,
      args: [...invocation.args],
      cwd,
      exit_code: exitCode,
      signal,
      timed_out: timedOut,
      cancelled,
      stdout: decoded.stdout.text,
      stderr: decoded.stderr.text,
      stdout_encoding: decoded.stdout.encoding,
      stderr_encoding: decoded.stderr.encoding,
      spawn_error: spawnError,
      log_path: logPath,
      runtime_log_path: runtimeLogPath,
      java_exception: javaException,
    };
  }

  private buildProcessFailureMessage(
    failureMessage: string,
    diagnostics: GhidraProcessDiagnostics
  ): string {
    return [
      `${failureMessage} with exit code ${diagnostics.exit_code}`,
      diagnostics.java_exception
        ? `${diagnostics.java_exception.exception_class}: ${diagnostics.java_exception.message}`
        : undefined,
      diagnostics.log_path ? `log_path=${diagnostics.log_path}` : undefined,
      diagnostics.runtime_log_path ? `runtime_log_path=${diagnostics.runtime_log_path}` : undefined,
    ]
      .filter((value): value is string => Boolean(value))
      .join(' | ');
  }

  private async runGhidraCommand(
    command: string,
    args: string[],
    cwd: string,
    timeoutMs: number,
    abortSignal: AbortSignal | undefined,
    timeoutMessage: string,
    failureMessage: string,
    logFilePath?: string,
    runtimeLogPath?: string
  ): Promise<GhidraCommandOutput> {
    const invocation = buildProcessInvocation(command, args);
    fs.mkdirSync(cwd, { recursive: true });

    return new Promise((resolve, reject) => {
      if (abortSignal?.aborted) {
        const decoded = decodeProcessStreams(Buffer.alloc(0), Buffer.alloc(0));
        const persistedLogPath = this.persistGhidraCommandLog(
          logFilePath,
          invocation,
          cwd,
          decoded,
          null,
          null,
          false,
          true
        );
        const diagnostics = this.buildProcessDiagnostics(
          invocation,
          cwd,
          decoded,
          null,
          null,
          false,
          true,
          undefined,
          persistedLogPath,
          runtimeLogPath
        );
        reject(
          new GhidraProcessError(
            'E_CANCELLED: Ghidra command cancelled before process start',
            diagnostics,
            'E_CANCELLED'
          )
        );
        return;
      }

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let timedOut = false;
      let cancelled = false;
      let settled = false;
      const childProcess: ChildProcess = this.spawnGhidraProcess(invocation, cwd);
      let onAbort: (() => void) | undefined;

      const settle = (fn: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        if (abortSignal && onAbort) {
          abortSignal.removeEventListener('abort', onAbort);
        }
        fn();
      };

      const timeoutTimer = setTimeout(() => {
        timedOut = true;
        settle(() => {
          childProcess.kill('SIGTERM');

          // Force kill after 5 seconds if still running
          setTimeout(() => {
            if (!childProcess.killed) {
              childProcess.kill('SIGKILL');
            }
          }, 5000);

          const decoded = decodeProcessStreams(
            Buffer.concat(stdoutChunks),
            Buffer.concat(stderrChunks)
          );
          const persistedLogPath = this.persistGhidraCommandLog(
            logFilePath,
            invocation,
            cwd,
            decoded,
            null,
            null,
            true,
            cancelled
          );
          const diagnostics = this.buildProcessDiagnostics(
            invocation,
            cwd,
            decoded,
            null,
            null,
            true,
            cancelled,
            undefined,
            persistedLogPath,
            runtimeLogPath
          );
          reject(new GhidraProcessError(timeoutMessage, diagnostics, 'E_TIMEOUT'));
        });
      }, timeoutMs);

      onAbort = () => {
        cancelled = true;
        settle(() => {
          childProcess.kill('SIGTERM');
          setTimeout(() => {
            if (!childProcess.killed) {
              childProcess.kill('SIGKILL');
            }
          }, 5000);
          const decoded = decodeProcessStreams(
            Buffer.concat(stdoutChunks),
            Buffer.concat(stderrChunks)
          );
          const persistedLogPath = this.persistGhidraCommandLog(
            logFilePath,
            invocation,
            cwd,
            decoded,
            null,
            null,
            false,
            true
          );
          const diagnostics = this.buildProcessDiagnostics(
            invocation,
            cwd,
            decoded,
            null,
            null,
            false,
            true,
            undefined,
            persistedLogPath
          );
          reject(
            new GhidraProcessError(
              'E_CANCELLED: Ghidra command cancelled by user',
              diagnostics,
              'E_CANCELLED'
            )
          );
        });
      };

      if (abortSignal) {
        abortSignal.addEventListener('abort', onAbort);
      }

      childProcess.stdout?.on('data', (data: Buffer) => {
        stdoutChunks.push(Buffer.from(data));
      });

      childProcess.stderr?.on('data', (data: Buffer) => {
        stderrChunks.push(Buffer.from(data));
      });

      childProcess.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
        settle(() => {
          clearTimeout(timeoutTimer);
          const decoded = decodeProcessStreams(
            Buffer.concat(stdoutChunks),
            Buffer.concat(stderrChunks)
          );
          const persistedLogPath = this.persistGhidraCommandLog(
            logFilePath,
            invocation,
            cwd,
            decoded,
            code,
            signal,
            timedOut,
            cancelled
          );
          const diagnostics = this.buildProcessDiagnostics(
            invocation,
            cwd,
            decoded,
            code,
            signal,
            timedOut,
            cancelled,
            undefined,
            persistedLogPath,
            runtimeLogPath
          );

          if (timedOut) {
            reject(new GhidraProcessError(timeoutMessage, diagnostics, 'E_TIMEOUT'));
            return;
          }

          if (cancelled) {
            reject(
              new GhidraProcessError(
                'E_CANCELLED: Ghidra command cancelled by user',
                diagnostics,
                'E_CANCELLED'
              )
            );
            return;
          }

          if (code !== 0) {
            reject(
              new GhidraProcessError(
                this.buildProcessFailureMessage(failureMessage, diagnostics),
                diagnostics,
                'E_GHIDRA_PROCESS'
              )
            );
            return;
          }

          resolve({
            stdout: decoded.stdout.text,
            stderr: decoded.stderr.text,
            diagnostics,
            command_log_path: persistedLogPath,
            runtime_log_path: runtimeLogPath,
          });
        });
      });

      childProcess.on('error', (error: Error) => {
        settle(() => {
          clearTimeout(timeoutTimer);
          const decoded = decodeProcessStreams(
            Buffer.concat(stdoutChunks),
            Buffer.concat(stderrChunks)
          );
          const persistedLogPath = this.persistGhidraCommandLog(
            logFilePath,
            invocation,
            cwd,
            decoded,
            null,
            null,
            timedOut,
            cancelled,
            error.message
          );
          const diagnostics = this.buildProcessDiagnostics(
            invocation,
            cwd,
            decoded,
            null,
            null,
            timedOut,
            cancelled,
            error.message,
            persistedLogPath,
            runtimeLogPath
          );
          reject(
            new GhidraProcessError(
              `Failed to spawn Ghidra process: ${error.message}${persistedLogPath ? ` | log_path=${persistedLogPath}` : ''}`,
              diagnostics,
              'E_SPAWN'
            )
          );
        });
      });
    });
  }

  private buildAnalyzeBaseArgs(
    projectPath: string,
    projectKey: string,
    options?: GhidraOptions
  ): string[] {
    const args: string[] = [projectPath, projectKey];
    const processor = options?.languageId || options?.processor;
    if (processor) {
      args.push('-processor', processor);
    }
    if (options?.cspec) {
      args.push('-cspec', options.cspec);
    }
    return args;
  }

  private buildScriptPath(options?: GhidraOptions): string {
    const scriptPaths = Array.from(
      new Set(
        [ghidraConfig.scriptsDir, ...(options?.scriptPaths || [])]
          .map((item) => item?.trim())
          .filter((item): item is string => Boolean(item))
      )
    );
    return scriptPaths.join(path.delimiter);
  }

  private buildAnalysisArgs(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    options: GhidraOptions
  ): string[] {
    const timeout = options.timeout || 300000; // Default 5 minutes
    const maxCpu = options.maxCpu || '4';

    return [
      ...this.buildAnalyzeBaseArgs(projectPath, projectKey, options),
      '-import',
      samplePath,
      '-max-cpu',
      maxCpu,
      '-analysisTimeoutPerFile',
      String(Math.floor(timeout / 1000)),
    ];
  }

  private buildExtractFunctionsArgs(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    scriptName: string,
    options?: GhidraOptions
  ): string[] {
    return [
      ...this.buildAnalyzeBaseArgs(projectPath, projectKey, options),
      '-process',
      path.basename(samplePath),
      '-scriptPath',
      this.buildScriptPath(options),
      '-postScript',
      scriptName,
      '-noanalysis',
    ];
  }

  private async executeMainAnalysis(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    options: GhidraOptions,
    sampleId: string
  ): Promise<GhidraCommandOutput> {
    const timeout = options.timeout || 300000; // Default 5 minutes
    const command = ghidraConfig.analyzeHeadlessPath;
    const logFilePath = this.buildGhidraCommandLogPath(sampleId, 'analyze_main', projectKey);
    const ghidraRuntimeLogPath = this.buildGhidraRuntimeLogPath(sampleId, 'analyze_main', projectKey);
    const args = [
      ...this.buildAnalysisArgs(projectPath, projectKey, samplePath, options),
      '-log',
      ghidraRuntimeLogPath,
    ];

    logger.debug(
      {
        command,
        args,
        timeout,
      },
      'Executing Ghidra Headless analysis phase'
    );

    try {
      return await this.runGhidraCommand(
        command,
        args,
        projectPath,
        timeout,
        options.abortSignal,
        `E_TIMEOUT: Ghidra analysis exceeded timeout of ${timeout}ms`,
        'Ghidra analysis failed',
        logFilePath,
        ghidraRuntimeLogPath
      );
    } catch (error) {
      if (error instanceof GhidraProcessError) {
        logger.error(
          {
            error_code: error.errorCode,
            raw_cmd: error.diagnostics.raw_cmd,
            exit_code: error.diagnostics.exit_code,
            timed_out: error.diagnostics.timed_out,
            stderr: error.diagnostics.stderr.substring(0, 1000),
            stderr_encoding: error.diagnostics.stderr_encoding,
          },
          'Ghidra analysis phase execution failed'
        );
      }
      throw error;
    }
  }

  private async executeFunctionExtractionScript(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    scriptName: string,
    timeoutMs: number,
    options?: GhidraOptions,
    sampleId?: string
  ): Promise<GhidraCommandOutput> {
    const command = ghidraConfig.analyzeHeadlessPath;
    const logFilePath = sampleId
      ? this.buildGhidraCommandLogPath(sampleId, `extract_${scriptName}`, projectKey)
      : undefined;
    const ghidraRuntimeLogPath = sampleId
      ? this.buildGhidraRuntimeLogPath(sampleId, `extract_${scriptName}`, projectKey)
      : undefined;
    const args = [
      ...this.buildExtractFunctionsArgs(projectPath, projectKey, samplePath, scriptName, options),
      ...(ghidraRuntimeLogPath ? ['-log', ghidraRuntimeLogPath] : []),
    ];

    logger.debug(
      {
        command,
        args,
        timeout: timeoutMs,
        script: scriptName,
      },
      'Executing Ghidra function extraction post-script'
    );

    return this.runGhidraCommand(
      command,
      args,
      projectPath,
      timeoutMs,
      undefined,
      `E_TIMEOUT: Function extraction (${scriptName}) exceeded timeout of ${timeoutMs}ms`,
      `Function extraction (${scriptName}) failed`,
      logFilePath,
      ghidraRuntimeLogPath
    );
  }

  private async tryExtractFunctionsWithFallback(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    timeoutMs: number,
    options?: GhidraOptions,
    sampleId?: string
  ): Promise<FunctionExtractionResult> {
    const warnings: string[] = [];
    const attempts: FunctionExtractionAttempt[] = [];

    const primaryScript = 'ExtractFunctions.java';
    const fallbackScript = 'ExtractFunctions.py';

    const runAndParse = async (scriptName: string): Promise<GhidraAnalysisOutput | undefined> => {
      let output: GhidraCommandOutput;
      try {
        output = await this.executeFunctionExtractionScript(
          projectPath,
          projectKey,
          samplePath,
          scriptName,
          timeoutMs,
          options,
          sampleId
        );
      } catch (error) {
        const diagnostics =
          error instanceof GhidraProcessError || error instanceof GhidraOutputParseError
            ? error.diagnostics
            : undefined;
        attempts.push({
          script: scriptName,
          diagnostics,
          command_log_path: diagnostics?.log_path,
          runtime_log_path: diagnostics?.runtime_log_path,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }

      try {
        const parsed = this.parseGhidraOutput(output.stdout, output.stderr, output.diagnostics);
        attempts.push({
          script: scriptName,
          stdout: output.stdout,
          stderr: output.stderr,
          diagnostics: output.diagnostics,
          command_log_path: output.command_log_path,
          runtime_log_path: output.runtime_log_path,
        });
        return parsed;
      } catch (parseError) {
        const parseMessage = parseError instanceof Error ? parseError.message : String(parseError);
        const diagnostics =
          parseError instanceof GhidraOutputParseError
            ? parseError.diagnostics
            : output.diagnostics;
        attempts.push({
          script: scriptName,
          stdout: output.stdout,
          stderr: output.stderr,
          diagnostics,
          command_log_path: output.command_log_path,
          runtime_log_path: output.runtime_log_path,
          parse_error: parseMessage,
          error: parseMessage,
        });
        throw parseError;
      }
    };

    const scriptOrder = [primaryScript, fallbackScript];

    for (const scriptName of scriptOrder) {
      try {
        const parsed = await runAndParse(scriptName);
        if (!parsed) {
          continue;
        }

        if (scriptName === fallbackScript) {
          warnings.push(
            `${primaryScript} failed in current Ghidra runtime. ` +
              `Falling back to ${fallbackScript}.`
          );
        }

        return {
          output: parsed,
          warnings,
          scriptUsed: scriptName,
          attempts,
        };
      } catch (scriptError) {
        const reason = scriptError instanceof Error ? scriptError.message : String(scriptError);
        if (scriptName === primaryScript) {
          warnings.push(
            `${primaryScript} failed in current Ghidra runtime. ` +
              `Falling back to ${fallbackScript}.`
          );
          continue;
        }

        warnings.push(`Function extraction failed with ${scriptName}: ${reason}`);
      }
    }

    const fallbackAttempt = attempts.find((item) => item.script === fallbackScript);
    if (fallbackAttempt?.error) {
      warnings.push(`Fallback ${fallbackScript} extraction failed: ${fallbackAttempt.error}`);
    }

    return {
      warnings,
      attempts,
    };
  }

  private selectProbeTarget(functions: GhidraFunction[]): string | undefined {
    const preferred =
      functions.find((item) => item.is_entry_point && !item.is_external) ||
      functions.find((item) => !item.is_external && !item.is_thunk) ||
      functions.find((item) => !item.is_external) ||
      functions[0];

    return preferred?.address;
  }

  private tryRecoverFunctionsFromPE(samplePath: string): FunctionRecoveryResult {
    const recovery = smartRecoverFunctionsFromPE(samplePath);
    const functions: GhidraFunction[] = recovery.functions.map((item: SmartRecoveredFunction) => ({
      address: item.address,
      name: item.name,
      size: item.size,
      is_thunk: false,
      is_external: false,
      calling_convention: 'unknown',
      signature: `${item.name}()`,
      callers: [],
      caller_count: 0,
      callees: [],
      callee_count: 0,
      caller_relationships: [],
      callee_relationships: [],
      is_entry_point: item.isEntryPoint,
      is_exported: item.isExported,
    }));

    return {
      functions,
      warnings: recovery.warnings,
      recoveryMetadata: {
        strategy: recovery.strategy,
        machine: recovery.machine,
        machine_name: recovery.machineName,
        image_base: recovery.imageBase,
        entry_point_rva: recovery.entryPointRva,
        count: recovery.count,
        recovered_functions: recovery.functions.map((item) => ({
          address: item.address,
          rva: item.rva,
          size: item.size,
          name: item.name,
          name_source: item.nameSource,
          confidence: item.confidence,
          source: item.source,
          section_name: item.sectionName,
          executable_section: item.executableSection,
          is_entry_point: item.isEntryPoint,
          is_exported: item.isExported,
          export_name: item.exportName,
          evidence: item.evidence,
        })),
      },
    };
  }

  private buildCapabilityReadyStatus(
    target: string,
    warnings?: string[]
  ): GhidraCapabilityStatus {
    return {
      available: true,
      status: 'ready',
      target,
      checked_at: new Date().toISOString(),
      warnings: warnings && warnings.length > 0 ? warnings : undefined,
    };
  }

  private buildCapabilityFailureStatus(
    capability: GhidraCapability,
    target: string | undefined,
    error: unknown
  ): GhidraCapabilityStatus {
    const diagnostics = getGhidraDiagnostics(error);
    const message = error instanceof Error ? error.message : String(error);
    const warnings: string[] = [];
    if (diagnostics?.stderr) {
      warnings.push(this.buildOutputSnippet(diagnostics.stderr, 600));
    } else if (diagnostics?.stdout) {
      warnings.push(this.buildOutputSnippet(diagnostics.stdout, 600));
    }

    return {
      available: false,
      status: 'degraded',
      reason:
        capability === 'decompile'
          ? `Decompile probe failed: ${message}`
          : `CFG probe failed: ${message}`,
      target,
      checked_at: new Date().toISOString(),
      warnings: warnings.length > 0 ? warnings : undefined,
      details: diagnostics
        ? {
            raw_cmd: diagnostics.raw_cmd,
            exit_code: diagnostics.exit_code,
            timed_out: diagnostics.timed_out,
            cancelled: diagnostics.cancelled,
            spawn_error: diagnostics.spawn_error,
            log_path: diagnostics.log_path,
            runtime_log_path: diagnostics.runtime_log_path,
            java_exception: diagnostics.java_exception,
          }
        : undefined,
    };
  }

  private async probeCapability(
    capability: GhidraCapability,
    projectPath: string,
    projectKey: string,
    samplePath: string,
    target: string,
    timeoutMs: number,
    sampleId?: string
  ): Promise<GhidraCapabilityProbeResult> {
    try {
      const output =
        capability === 'decompile'
        ? await this.executeDecompileScript(
              projectPath,
              projectKey,
              samplePath,
              target,
              false,
              timeoutMs,
              sampleId
            )
          : await this.executeCFGScript(
              projectPath,
              projectKey,
              samplePath,
              target,
              timeoutMs,
              sampleId
            );

      if (capability === 'decompile') {
        const parsed = this.parseDecompileOutput(output.stdout, output.stderr);
        if ('error' in parsed) {
          throw new Error(parsed.error);
        }
      } else {
        const parsed = this.parseCFGOutput(output.stdout, output.stderr);
        if ('error' in parsed) {
          throw new Error(parsed.error);
        }
      }

      return {
        status: this.buildCapabilityReadyStatus(target),
        output,
      };
    } catch (error) {
      return {
        status: this.buildCapabilityFailureStatus(capability, target, error),
      };
    }
  }

  private resolveAnalysisProject(
    sampleId: string,
    analysis: Analysis
  ): { analysis: Analysis; projectPath: string; projectKey: string } {
    const metadata = parseGhidraAnalysisMetadata(analysis.output_json);
    const projectPath = typeof metadata.project_path === 'string' ? metadata.project_path : '';
    const projectKey = typeof metadata.project_key === 'string' ? metadata.project_key : '';

    if (!projectPath || !projectKey) {
      throw new Error(
        `Ghidra analysis ${analysis.id} has no reusable project metadata for downstream scripts.`
      );
    }

    if (fs.existsSync(projectPath)) {
      return {
        analysis,
        projectPath,
        projectKey,
      };
    }

    const recoveredProject = this.findRecoveredProject(sampleId, projectPath);
    if (recoveredProject) {
      logger.warn(
        {
          sampleId,
          analysisId: analysis.id,
          originalProjectPath: projectPath,
          recoveredProjectPath: recoveredProject.projectPath,
          recoveredProjectKey: recoveredProject.projectKey,
        },
        'Recorded Ghidra project path is missing; using recovered project path from sample ghidra workspace'
      );
      return {
        analysis,
        projectPath: recoveredProject.projectPath,
        projectKey: recoveredProject.projectKey,
      };
    }

    return {
      analysis,
      projectPath,
      projectKey,
    };
  }

  private resolveGhidraAnalysisForCapability(
    sampleId: string,
    capability: GhidraCapability
  ): { analysis: Analysis; projectPath: string; projectKey: string; readiness: GhidraCapabilityStatus } {
    const analyses = this.database.findAnalysesBySample(sampleId);
    const selected = findBestGhidraAnalysis(analyses, capability);
    if (!selected) {
      const capabilityLabel =
        capability === 'function_index'
          ? 'function index'
          : capability === 'decompile'
            ? 'decompile'
            : 'cfg';
      throw new Error(
        `No Ghidra analysis with ${capabilityLabel} readiness found for sample: ${sampleId}. Please run ghidra.analyze first.`
      );
    }

    const readiness = getGhidraCapabilityStatus(selected, capability);
    if (!isGhidraCapabilityReady(selected, capability)) {
      const reason = readiness.reason ? ` ${readiness.reason}` : '';
      throw new Error(
        `Ghidra ${capability} is not ready for sample: ${sampleId}.${reason}`.trim()
      );
    }

    const project = this.resolveAnalysisProject(sampleId, selected);
    return {
      ...project,
      readiness,
    };
  }

  /**
   * Analyze a sample with Ghidra Headless
   * 
   * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
   * 
   * @param sampleId - Sample identifier
   * @param options - Ghidra analysis options
   * @returns Analysis result with function count and project path
   */
  async analyze(sampleId: string, options: GhidraOptions = {}): Promise<AnalysisResult> {
    // Check if Ghidra is configured
    if (!ghidraConfig.isValid) {
      throw new Error(
        'Ghidra is not properly configured. Please set GHIDRA_PATH or GHIDRA_INSTALL_DIR environment variable.'
      );
    }

    const startTime = Date.now();
    const progressStages: Array<{
      progress: number;
      stage: string;
      detail: string | null;
      recorded_at: string;
    }> = [];
    const trackProgress = (progress: number, stage: string, detail?: string) => {
      progressStages.push({
        progress: Math.max(0, Math.min(100, Math.round(progress))),
        stage,
        detail: typeof detail === 'string' ? detail : null,
        recorded_at: new Date().toISOString(),
      });
      this.reportProgress(options, progress, stage, detail);
    };
    const sample = this.database.findSample(sampleId);
    if (!sample) {
      throw new Error(`Sample not found: ${sampleId}`);
    }

    // 1. Create analysis record (Requirement 8.2)
    const analysisId = options.analysisId || randomUUID();
    this.database.insertAnalysis({
      id: analysisId,
      sample_id: sampleId,
      stage: 'ghidra',
      backend: 'ghidra',
      status: 'running',
      started_at: new Date().toISOString(),
      finished_at: null,
      output_json: null,
      metrics_json: null
    });

    logger.info({
      analysisId,
      sampleId,
      options
    }, 'Starting Ghidra analysis');
    trackProgress(5, 'starting', 'Preparing Ghidra analysis');

    try {
      // 2. Get sample information
      trackProgress(10, 'sample_loaded', 'Sample metadata loaded');

      // 3. Get workspace paths
      const workspace = await this.workspaceManager.getWorkspace(sampleId);
      const samplePath = await this.resolveSamplePathForSample(sampleId);
      trackProgress(20, 'sample_resolved', samplePath);

      // Verify sample file exists
      if (!fs.existsSync(samplePath)) {
        throw new Error(`Sample file not found: ${samplePath}`);
      }

      // 4. Create isolated Ghidra project space (Requirement 8.1, 8.7)
      const ghidraProjectRoot = getSampleScopedGhidraProjectRoot(sampleId);
      const { projectPath, projectKey } = createGhidraProject(
        ghidraProjectRoot,
        options.projectKey
      );
      trackProgress(30, 'project_created', projectPath);

      logger.debug({
        projectPath,
        projectKey,
        sampleId
      }, 'Created Ghidra project');

      // 5. Execute main Ghidra analysis/import phase
      const mainAnalysisOutput = await this.executeMainAnalysis(
        projectPath,
        projectKey,
        samplePath,
        options,
        sampleId
      );
      trackProgress(55, 'main_analysis_complete', projectKey);

      // 6. Execute post-processing function extraction with fallback chain.
      // If extraction fails but main analysis succeeded, persist partial_success.
      const extraction = await this.tryExtractFunctionsWithFallback(
        projectPath,
        projectKey,
        samplePath,
        options.timeout || 300000,
        options,
        sampleId
      );
      trackProgress(72, 'function_extraction_complete', extraction.scriptUsed || 'fallback_completed');
      const analysisOutput = extraction.output;
      const extractionWarnings = extraction.warnings || [];
      const extractionAttempts = extraction.attempts || [];
      let recoveredFunctions: FunctionRecoveryResult | undefined;
      const combinedWarnings = [...extractionWarnings];
      const analysisOutputHasFunctions = Boolean(
        analysisOutput && analysisOutput.functions.length > 0
      );
      const shouldRecoverFromPE = !analysisOutput || !analysisOutputHasFunctions;
      if (analysisOutput && !analysisOutputHasFunctions) {
        combinedWarnings.push(
          'Ghidra post-script extraction completed but returned zero functions; attempting PE metadata recovery from .pdata / exception directory.'
        );
      }
      if (shouldRecoverFromPE) {
        try {
          recoveredFunctions = this.tryRecoverFunctionsFromPE(samplePath);
          if (recoveredFunctions.functions.length > 0) {
            combinedWarnings.push(
              `Recovered ${recoveredFunctions.functions.length} function candidates from PE exception metadata after Ghidra post-script extraction failed.`
            );
          }
          if (recoveredFunctions.warnings.length > 0) {
            combinedWarnings.push(...recoveredFunctions.warnings);
          }
        } catch (recoveryError) {
          combinedWarnings.push(
            `PE metadata recovery failed after Ghidra extraction failure: ${
              recoveryError instanceof Error ? recoveryError.message : String(recoveryError)
            }`
          );
        }
      }
      const effectiveFunctions = analysisOutputHasFunctions
        ? analysisOutput?.functions || []
        : recoveredFunctions?.functions || [];
      const probeTarget = analysisOutputHasFunctions
        ? this.selectProbeTarget((analysisOutput?.functions || []))
        : undefined;
      let decompileProbe: GhidraCapabilityProbeResult | undefined;
      let cfgProbe: GhidraCapabilityProbeResult | undefined;

      if (effectiveFunctions.length > 0) {
        // 7. Store functions to database (Requirement 8.4)
        await this.storeFunctions(sampleId, effectiveFunctions);
        trackProgress(84, 'functions_stored', String(effectiveFunctions.length));

        // 8. Store analysis artifact
        const artifactId = randomUUID();
        const artifactPath = analysisOutput
          ? `ghidra/functions_${projectKey}.json`
          : `ghidra/recovered_functions_${projectKey}.json`;
        const artifactFullPath = path.join(workspace.root, artifactPath);

        // Ensure directory exists
        const artifactDir = path.dirname(artifactFullPath);
        if (!fs.existsSync(artifactDir)) {
          fs.mkdirSync(artifactDir, { recursive: true });
        }

        // Write artifact
        const artifactPayload =
          (analysisOutputHasFunctions ? analysisOutput : undefined) ||
          {
            program_name: path.basename(samplePath),
            program_path: samplePath,
            function_count: recoveredFunctions?.functions.length || 0,
            functions: recoveredFunctions?.functions || [],
            recovery: recoveredFunctions?.recoveryMetadata || {},
          };
        fs.writeFileSync(artifactFullPath, JSON.stringify(artifactPayload, null, 2));

        // Compute artifact SHA256
        const artifactSha256 = createHash('sha256')
          .update(JSON.stringify(artifactPayload))
          .digest('hex');

        // Insert artifact record
        this.database.insertArtifact({
          id: artifactId,
          sample_id: sampleId,
          type: analysisOutputHasFunctions ? 'ghidra_functions' : 'function_recovery',
          path: artifactPath,
          sha256: artifactSha256,
          mime: 'application/json',
          created_at: new Date().toISOString()
        });

        if (analysisOutput && probeTarget) {
          const probeTimeoutMs = Math.max(
            5000,
            Math.min(15000, Math.floor((options.timeout || 300000) / 6))
          );
          decompileProbe = await this.probeCapability(
            'decompile',
            projectPath,
            projectKey,
            samplePath,
            probeTarget,
            probeTimeoutMs,
            sampleId
          );
          cfgProbe = await this.probeCapability(
            'cfg',
            projectPath,
            projectKey,
            samplePath,
            probeTarget,
            probeTimeoutMs,
            sampleId
          );
        }
      }
      // 9. Update analysis status
      const elapsedMs = Date.now() - startTime;
      const status: 'done' | 'partial_success' = analysisOutputHasFunctions ? 'done' : 'partial_success';
      const functionCount = analysisOutputHasFunctions
        ? analysisOutput?.function_count || analysisOutput?.functions.length || 0
        : recoveredFunctions?.functions.length || 0;
      const functionIndexRecovered =
        !analysisOutputHasFunctions && Boolean(recoveredFunctions && functionCount > 0);
      const functionIndexReady = Boolean(analysisOutputHasFunctions && functionCount > 0);
      const readiness = {
        function_index: {
          available: functionIndexReady || functionIndexRecovered,
          status: functionIndexReady ? 'ready' : functionIndexRecovered ? 'degraded' : 'missing',
          reason: functionIndexRecovered
            ? 'Function candidates were recovered from PE exception metadata (.pdata) after Ghidra post-script extraction failed.'
            : undefined,
          checked_at: new Date().toISOString(),
          warnings:
            combinedWarnings.length > 0 ? combinedWarnings : undefined,
        } satisfies GhidraCapabilityStatus,
        decompile: functionIndexReady
          ? decompileProbe?.status ||
            ({
              available: false,
              status: 'missing',
              reason: 'No decompile probe target was available from extracted functions.',
              checked_at: new Date().toISOString(),
            } satisfies GhidraCapabilityStatus)
          : ({
              available: false,
              status: 'missing',
              reason: functionIndexRecovered
                ? 'Function candidates were recovered from PE metadata only; Ghidra decompile readiness was not established.'
                : 'Function index is unavailable, so decompile readiness was not probed.',
              checked_at: new Date().toISOString(),
            } satisfies GhidraCapabilityStatus),
        cfg: functionIndexReady
          ? cfgProbe?.status ||
            ({
              available: false,
              status: 'missing',
              reason: 'No CFG probe target was available from extracted functions.',
              checked_at: new Date().toISOString(),
            } satisfies GhidraCapabilityStatus)
          : ({
              available: false,
              status: 'missing',
              reason: functionIndexRecovered
                ? 'Function candidates were recovered from PE metadata only; Ghidra CFG readiness was not established.'
                : 'Function index is unavailable, so CFG readiness was not probed.',
              checked_at: new Date().toISOString(),
          } satisfies GhidraCapabilityStatus),
      };
      trackProgress(94, 'readiness_recorded', status);
      const commandLogPaths = Array.from(
        new Set(
          [
            mainAnalysisOutput.command_log_path,
            ...extractionAttempts.map((attempt) => attempt.command_log_path || attempt.diagnostics?.log_path),
            decompileProbe?.output?.command_log_path,
            cfgProbe?.output?.command_log_path,
          ]
            .filter((item): item is string => typeof item === 'string')
            .map((item) => item.trim())
            .filter((item) => item.length > 0)
        )
      );
      const runtimeLogPaths = Array.from(
        new Set(
          [
            mainAnalysisOutput.runtime_log_path,
            ...extractionAttempts.map(
              (attempt) => attempt.runtime_log_path || attempt.diagnostics?.runtime_log_path
            ),
            decompileProbe?.output?.runtime_log_path,
            cfgProbe?.output?.runtime_log_path,
          ]
            .filter((item): item is string => typeof item === 'string')
            .map((item) => item.trim())
            .filter((item) => item.length > 0)
        )
      );
      const javaException =
        mainAnalysisOutput.diagnostics.java_exception ||
        extractionAttempts.find((attempt) => attempt.diagnostics?.java_exception)?.diagnostics
          ?.java_exception ||
        decompileProbe?.output?.diagnostics.java_exception ||
        cfgProbe?.output?.diagnostics.java_exception;
      this.database.updateAnalysis(analysisId, {
        status,
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          function_count: functionCount,
          project_path: projectPath,
          project_key: projectKey,
          readiness,
          function_extraction: {
            status: analysisOutputHasFunctions
              ? 'success'
              : functionIndexRecovered
                ? 'recovered_via_smart_recover'
                : 'failed',
            script_used: extraction.scriptUsed,
            warnings: combinedWarnings,
            attempts: extractionAttempts,
          },
          function_recovery: recoveredFunctions?.recoveryMetadata,
          end_to_end_probe: {
            target: probeTarget,
            decompile: decompileProbe?.status,
            cfg: cfgProbe?.status,
            checked_at: new Date().toISOString(),
          },
          ghidra_execution: {
            project_root: getConfiguredGhidraProjectRoot(),
            log_root: getConfiguredGhidraLogRoot(),
            command_log_paths: commandLogPaths,
            runtime_log_paths: runtimeLogPaths,
            progress_stages: progressStages,
            java_exception: javaException,
          },
        }),
        metrics_json: JSON.stringify({
          elapsed_ms: elapsedMs,
          function_count: functionCount
        })
      });

      if (status === 'done') {
        logger.info({
          analysisId,
          sampleId,
          functionCount,
          elapsedMs,
          function_extraction_script: extraction.scriptUsed,
          readiness,
        }, 'Ghidra analysis completed successfully');
      } else {
        logger.warn({
          analysisId,
          sampleId,
          elapsedMs,
          function_extraction_warnings: extractionWarnings,
          readiness,
        }, 'Ghidra analysis completed with partial_success (function extraction failed)');
      }
      trackProgress(100, 'completed', status);

      return {
        analysisId,
        backend: 'ghidra',
        functionCount,
        projectPath,
        status,
        warnings: combinedWarnings.length > 0 ? combinedWarnings : undefined,
        readiness,
      };

    } catch (error) {
      // Handle failure (Requirement 8.5, 8.6)
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      const elapsedMs = Date.now() - startTime;

      logger.error({
        analysisId,
        sampleId,
        error: errorMessage,
        ghidra_diagnostics: diagnostics,
        elapsedMs
      }, 'Ghidra analysis failed');

      // Update analysis status to failed
      const cancelled =
        error instanceof GhidraProcessError && error.errorCode === 'E_CANCELLED';

      this.database.updateAnalysis(analysisId, {
        status: cancelled ? 'cancelled' : 'failed',
        finished_at: new Date().toISOString(),
        output_json: JSON.stringify({
          error: errorMessage,
          ghidra_diagnostics: diagnostics,
          ghidra_execution: {
            project_root: getConfiguredGhidraProjectRoot(),
            log_root: getConfiguredGhidraLogRoot(),
            command_log_paths: diagnostics?.log_path ? [diagnostics.log_path] : [],
            runtime_log_paths: diagnostics?.runtime_log_path ? [diagnostics.runtime_log_path] : [],
            progress_stages: progressStages,
            java_exception: diagnostics?.java_exception,
          },
        }),
        metrics_json: JSON.stringify({
          elapsed_ms: elapsedMs
        })
      });

      throw error;
    }
  }

  /**
   * List functions from the functions table
   * 
   * Requirements: 9.1
   * 
   * @param sampleId - Sample identifier
   * @param limit - Optional limit on number of functions to return
   * @returns Array of function information
   */
  async listFunctions(sampleId: string, limit?: number): Promise<FunctionInfo[]> {
    logger.debug({ sampleId, limit }, 'Listing functions');

    // Query functions from database
    const dbFunctions = this.database.findFunctions(sampleId);

    if (dbFunctions.length === 0) {
      logger.warn({ sampleId }, 'No functions found for sample');
      return [];
    }

    // Convert database functions to FunctionInfo format
    const functionInfos: FunctionInfo[] = dbFunctions.map(func => ({
      name: func.name || 'unknown',
      address: func.address,
      size: func.size || 0,
      callers: func.caller_count || 0,
      callees: func.callee_count || 0
    }));

    // Apply limit if specified
    if (limit !== undefined && limit > 0) {
      return functionInfos.slice(0, limit);
    }

    logger.info({
      sampleId,
      functionCount: functionInfos.length
    }, 'Functions listed successfully');

    return functionInfos;
  }

  /**
   * Rank functions by interest score
   * 
   * Requirements: 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8
   * 
   * Scoring rules:
   * - Large functions (> 1000 bytes): +10 points (Requirement 9.3)
   * - High caller count (> 10): +5 * log(callers) points (Requirement 9.4)
   * - Calls sensitive APIs: +15 points (Requirement 9.5)
   * - Entry point or exported: +20 points (Requirement 9.6)
   * 
   * @param sampleId - Sample identifier
   * @param topK - Number of top functions to return (default: 20)
   * @returns Array of ranked functions with scores and reasons
   */
  async rankFunctions(sampleId: string, topK: number = 20): Promise<RankedFunction[]> {
    logger.debug({ sampleId, topK }, 'Ranking functions');

    // 1. Get all functions from database
    const functions = this.database.findFunctions(sampleId);

    if (functions.length === 0) {
      logger.warn({ sampleId }, 'No functions found for ranking');
      return [];
    }

    // 2. Define sensitive APIs (Requirement 9.5)
    const sensitiveAPIs = [
      'CreateProcess',
      'CreateProcessA',
      'CreateProcessW',
      'WriteFile',
      'WriteFileEx',
      'RegSetValue',
      'RegSetValueEx',
      'RegSetValueExA',
      'RegSetValueExW',
      'InternetOpen',
      'InternetOpenA',
      'InternetOpenW',
      'InternetConnect',
      'HttpOpenRequest',
      'HttpSendRequest',
      'URLDownloadToFile',
      'WinExec',
      'ShellExecute',
      'ShellExecuteA',
      'ShellExecuteW',
      'VirtualAlloc',
      'VirtualAllocEx',
      'CreateRemoteThread',
      'WriteProcessMemory',
      'SetWindowsHookEx',
      'GetProcAddress',
      'LoadLibrary',
      'LoadLibraryA',
      'LoadLibraryW'
    ];
    const dynamicResolverAPIs = new Set(['GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW'])
    const dynamicResolverLookup = new Set(Array.from(dynamicResolverAPIs, (item) => item.toLowerCase()))
    const normalizeApiName = (value: string): string => value.toLowerCase()

    // 3. Calculate score for each function
    const rankedFunctions: RankedFunction[] = functions.map(func => {
      let score = 0.0;
      const reasons: string[] = [];
      const xrefSummary: FunctionXrefSummary[] = [];

      // Rule 1: Large function (> 1000 bytes) - Requirement 9.3
      if (func.size && func.size > 1000) {
        score += 10.0;
        reasons.push('large_function');
      }

      // Rule 2: High caller count (> 10) - Requirement 9.4
      if (func.caller_count && func.caller_count > 10) {
        const callerScore = 5.0 * Math.log(func.caller_count);
        score += callerScore;
        reasons.push('high_callers');
      }

      // Rule 3: Calls sensitive APIs - Requirement 9.5
      if (func.callees) {
        try {
          const callees = JSON.parse(func.callees) as string[];
          const matchedAPIs = callees.filter(callee =>
            sensitiveAPIs.some(api => callee.includes(api))
          );
          const normalizedMatched = new Set(matchedAPIs.map(normalizeApiName))
          const hasDynamicResolver = Array.from(dynamicResolverAPIs).some((api) =>
            normalizedMatched.has(api.toLowerCase())
          )

          if (matchedAPIs.length > 0) {
            score += 15.0;
            matchedAPIs.forEach(api => {
              reasons.push(`calls_sensitive_api:${api}`);

              const provenance: FunctionXrefSummary['provenance'] = dynamicResolverLookup.has(
                normalizeApiName(api)
              )
                ? 'dynamic_resolution_api'
                : hasDynamicResolver
                  ? 'dynamic_resolution_helper'
                  : 'static_named_call'
              const confidence =
                provenance === 'dynamic_resolution_api'
                  ? 0.9
                  : provenance === 'dynamic_resolution_helper'
                    ? 0.62
                    : 0.78
              const evidence =
                provenance === 'dynamic_resolution_helper'
                  ? [
                      `callee:${api}`,
                      ...matchedAPIs
                        .filter((item) => dynamicResolverLookup.has(normalizeApiName(item)))
                        .slice(0, 2)
                        .map((item) => `resolver:${item}`),
                    ]
                  : [`callee:${api}`]
              xrefSummary.push({
                api,
                provenance,
                confidence,
                evidence,
              })
            });
          }
        } catch (error) {
          logger.warn({
            sampleId,
            address: func.address,
            error: error instanceof Error ? error.message : String(error)
          }, 'Failed to parse callees JSON');
        }
      }

      // Rule 4: Entry point or exported function - Requirement 9.6
      if (func.is_entry_point === 1 || func.is_exported === 1) {
        score += 20.0;
        if (func.is_entry_point === 1) {
          reasons.push('entry_point');
        }
        if (func.is_exported === 1) {
          reasons.push('exported');
        }
      }

      return {
        address: func.address,
        name: func.name || 'unknown',
        score,
        reasons,
        xref_summary: xrefSummary.length > 0 ? xrefSummary : undefined,
      };
    });

    // 4. Sort by score descending
    rankedFunctions.sort((a, b) => b.score - a.score);

    // 5. Update functions table with scores and tags (Requirement 9.7)
    for (const rankedFunc of rankedFunctions) {
      this.database.updateFunction(sampleId, rankedFunc.address, {
        score: rankedFunc.score,
        tags: JSON.stringify(rankedFunc.reasons)
      });
    }

    // 6. Return top K functions (Requirement 9.8)
    const topFunctions = rankedFunctions.slice(0, topK);

    logger.info({
      sampleId,
      totalFunctions: functions.length,
      topK,
      topScore: topFunctions[0]?.score || 0
    }, 'Functions ranked successfully');

    return topFunctions;
  }

  async searchFunctions(
    sampleId: string,
    options: {
      apiQuery?: string;
      stringQuery?: string;
      limit?: number;
      timeout?: number;
    }
  ): Promise<FunctionSearchResult> {
    const apiQuery = options.apiQuery?.trim() || '';
    const stringQuery = options.stringQuery?.trim() || '';
    const limit = Math.max(1, options.limit || 20);

    if (!apiQuery && !stringQuery) {
      throw new Error('At least one of apiQuery or stringQuery must be provided.');
    }

    const sample = this.database.findSample(sampleId);
    if (!sample) {
      throw new Error(`Sample not found: ${sampleId}`);
    }

    if (!stringQuery) {
      try {
        if (ghidraConfig.isValid) {
          return await this.searchFunctionsWithGhidra(
            sampleId,
            apiQuery,
            '',
            limit,
            options.timeout || 30000
          );
        }
      } catch (error) {
        logger.warn(
          {
            sampleId,
            apiQuery,
            error: error instanceof Error ? error.message : String(error),
          },
          'Falling back to function-index API search after Ghidra search failure'
        );
      }

      return this.searchFunctionsFromIndex(sampleId, apiQuery, limit);
    }

    if (!ghidraConfig.isValid) {
      throw new Error(
        'Ghidra is required for string-to-function reverse lookup. Please set GHIDRA_PATH or GHIDRA_INSTALL_DIR and run ghidra.analyze first.'
      );
    }

    return this.searchFunctionsWithGhidra(
      sampleId,
      apiQuery,
      stringQuery,
      limit,
      options.timeout || 30000
    );
  }

  async analyzeCrossReferences(
    sampleId: string,
    options: {
      targetType: 'function' | 'api' | 'string' | 'data'
      query: string
      depth?: number
      limit?: number
      timeout?: number
    }
  ): Promise<CrossReferenceAnalysis> {
    if (!ghidraConfig.isValid) {
      throw new Error(
        'Ghidra is not properly configured. Please set GHIDRA_PATH or GHIDRA_INSTALL_DIR environment variable.'
      )
    }

    const sample = this.database.findSample(sampleId)
    if (!sample) {
      throw new Error(`Sample not found: ${sampleId}`)
    }

    const resolved = this.resolveGhidraAnalysisForCapability(sampleId, 'function_index')
    await this.workspaceManager.getWorkspace(sampleId)
    const samplePath = await this.resolveSamplePathForSample(sampleId)
    if (!fs.existsSync(samplePath)) {
      throw new Error(`Sample file not found: ${samplePath}`)
    }

    const depth = Math.max(1, Math.min(options.depth || 1, 3))
    const limit = Math.max(1, Math.min(options.limit || 20, 100))
    const timeout = options.timeout || 30000

    return this.runWithProjectLockRetry(
      'Cross-reference analysis',
      async () => {
        const output = await this.executeCrossReferenceScript(
          resolved.projectPath,
          resolved.projectKey,
          samplePath,
          options.targetType,
          options.query,
          depth,
          limit,
          timeout,
          sampleId
        )

        const result = this.parseCrossReferenceOutput(
          output.stdout,
          output.stderr,
          output.diagnostics
        )
        if ('error' in result) {
          throw result.diagnostics
            ? new GhidraOutputParseError(result.error as string, result.diagnostics)
            : new Error(result.error as string)
        }

        return result as CrossReferenceAnalysis
      },
      {
        sampleId,
        targetType: options.targetType,
        query: options.query,
      }
    )
  }

  /**
   * Decompile a specific function
   * 
   * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6
   * 
   * @param sampleId - Sample identifier
   * @param addressOrSymbol - Function address (hex string) or symbol name
   * @param includeXrefs - Whether to include cross-references (default: false)
   * @param timeout - Timeout in milliseconds (default: 30000)
   * @returns Decompiled function with pseudocode, callers, callees, and optional xrefs
   */
  async decompileFunction(
    sampleId: string,
    addressOrSymbol: string,
    includeXrefs: boolean = false,
    timeout: number = 30000
  ): Promise<DecompiledFunction> {
    // Check if Ghidra is configured
    if (!ghidraConfig.isValid) {
      throw new Error(
        'Ghidra is not properly configured. Please set GHIDRA_PATH or GHIDRA_INSTALL_DIR environment variable.'
      );
    }

    logger.debug({
      sampleId,
      addressOrSymbol,
      includeXrefs,
      timeout
    }, 'Decompiling function');

    // 1. Validate that the sample has been analyzed
    const sample = this.database.findSample(sampleId);
    if (!sample) {
      throw new Error(`Sample not found: ${sampleId}`);
    }

    const resolved = this.resolveGhidraAnalysisForCapability(sampleId, 'decompile');

    // 2. Get workspace and project paths
    await this.workspaceManager.getWorkspace(sampleId);
    const samplePath = await this.resolveSamplePathForSample(sampleId);

    // Verify sample file exists
    if (!fs.existsSync(samplePath)) {
      throw new Error(`Sample file not found: ${samplePath}`);
    }

    // 3. Reuse the Ghidra project from the capability-ready analysis
    const { projectPath, projectKey } = resolved;

    // 4. Execute DecompileFunction.py script
    try {
      const result = await this.runWithProjectLockRetry(
        'Function decompilation',
        async () => {
          const output = await this.executeDecompileScript(
            projectPath,
            projectKey,
            samplePath,
            addressOrSymbol,
            includeXrefs,
            timeout,
            sampleId
          );

          const parsed = this.parseDecompileOutput(
            output.stdout,
            output.stderr,
            output.diagnostics
          );
          if ('error' in parsed) {
            throw parsed.diagnostics
              ? new GhidraOutputParseError(parsed.error as string, parsed.diagnostics)
              : new Error(parsed.error as string);
          }

          return parsed as DecompiledFunction;
        },
        {
          sampleId,
          addressOrSymbol,
          includeXrefs,
        }
      );

      logger.info({
        sampleId,
        function: result.function,
        address: result.address,
        pseudocodeLength: result.pseudocode?.length || 0,
        callerCount: result.callers?.length || 0,
        calleeCount: result.callees?.length || 0,
        xrefCount: result.xrefs?.length || 0
      }, 'Function decompiled successfully');

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      logger.error({
        sampleId,
        addressOrSymbol,
        error: errorMessage,
        ghidra_diagnostics: diagnostics
      }, 'Function decompilation failed');
      throw error;
    }
  }

  private buildOutputSnippet(output: string, limit: number = 1200): string {
    const normalized = output.replace(/\0/g, '').trim();
    if (normalized.length === 0) {
      return '(empty)';
    }
    if (normalized.length <= limit) {
      return normalized;
    }
    const truncated = normalized.slice(0, limit);
    return `${truncated}... (truncated ${normalized.length - limit} chars)`;
  }

  private buildSyntheticDiagnostics(stdout: string, stderr: string): GhidraProcessDiagnostics {
    return {
      raw_cmd: 'unknown',
      command: 'unknown',
      args: [],
      cwd: process.cwd(),
      exit_code: 0,
      signal: null,
      timed_out: false,
      cancelled: false,
      stdout,
      stderr,
      stdout_encoding: 'utf-8',
      stderr_encoding: 'utf-8',
    };
  }

  private buildNoJsonOutputMessage(
    stage: string,
    stdout: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): string {
    const rawCommand = diagnostics?.raw_cmd ? `raw_cmd=${diagnostics.raw_cmd}` : undefined;
    const logPath = diagnostics?.log_path ? `log_path=${diagnostics.log_path}` : undefined;
    const javaException = diagnostics?.java_exception
      ? `java_exception=${diagnostics.java_exception.exception_class}: ${diagnostics.java_exception.message}`
      : undefined;
    const lockHint = /unable to lock project|lockexception/i.test(`${stdout}\n${stderr}`)
      ? 'signal_hint=project_lock_detected'
      : undefined;
    return [
      `${stage}: No JSON output found`,
      rawCommand,
      logPath,
      javaException,
      lockHint,
      `stdout_snippet=${this.buildOutputSnippet(stdout)}`,
      `stderr_snippet=${this.buildOutputSnippet(stderr)}`,
    ]
      .filter((value): value is string => Boolean(value))
      .join(' | ');
  }

  private normalizeNamedAddressList(raw: unknown): Array<{ address: string; name: string }> {
    if (!Array.isArray(raw)) {
      return [];
    }

    const normalized: Array<{ address: string; name: string }> = [];
    const seen = new Set<string>();

    for (const item of raw) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      const typed = item as Record<string, unknown>;
      const address = typeof typed.address === 'string' ? typed.address : '';
      const name = typeof typed.name === 'string' ? typed.name : '';
      if (!address && !name) {
        continue;
      }
      const key = `${address}|${name}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      normalized.push({ address, name });
    }

    return normalized;
  }

  private normalizeStringArray(raw: unknown): string[] {
    if (!Array.isArray(raw)) {
      return [];
    }
    return Array.from(
      new Set(raw.filter((item): item is string => typeof item === 'string' && item.trim().length > 0))
    );
  }

  private normalizeFunctionRelationships(raw: unknown): FunctionRelationship[] {
    if (!Array.isArray(raw)) {
      return [];
    }

    const normalized: FunctionRelationship[] = [];
    const seen = new Set<string>();

    for (const item of raw) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      const typed = item as Record<string, unknown>;
      const address = typeof typed.address === 'string' ? typed.address : '';
      const name = typeof typed.name === 'string' ? typed.name : '';
      const relationTypes = this.normalizeStringArray(typed.relation_types);
      const referenceTypes = this.normalizeStringArray(typed.reference_types);
      const referenceAddresses = this.normalizeStringArray(typed.reference_addresses);
      const targetAddresses = this.normalizeStringArray(typed.target_addresses);
      const resolvedBy = typeof typed.resolved_by === 'string' ? typed.resolved_by : undefined;
      const isExact = typeof typed.is_exact === 'boolean' ? typed.is_exact : undefined;

      if (!address && !name && relationTypes.length === 0) {
        continue;
      }

      const key = `${address}|${name}|${relationTypes.join(',')}|${referenceTypes.join(',')}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);

      normalized.push({
        address,
        name,
        relation_types: relationTypes,
        reference_types: referenceTypes,
        reference_addresses: referenceAddresses,
        target_addresses: targetAddresses.length > 0 ? targetAddresses : undefined,
        resolved_by: resolvedBy,
        is_exact: isExact,
      });
    }

    return normalized;
  }

  private normalizeCrossReferences(raw: unknown): CrossReference[] {
    if (!Array.isArray(raw)) {
      return [];
    }

    const normalized: CrossReference[] = [];
    for (const item of raw) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      const typed = item as Record<string, unknown>;
      if (typeof typed.from_address !== 'string' || typeof typed.type !== 'string') {
        continue;
      }
      normalized.push({
        from_address: typed.from_address,
        type: typed.type,
        is_call: Boolean(typed.is_call),
        is_data: Boolean(typed.is_data),
        from_function: typeof typed.from_function === 'string' ? typed.from_function : undefined,
      });
    }

    return normalized;
  }

  private normalizeCrossReferenceNodes(raw: unknown): CrossReferenceNode[] {
    if (!Array.isArray(raw)) {
      return [];
    }

    const normalized: CrossReferenceNode[] = []
    const seen = new Set<string>()
    for (const item of raw) {
      if (!item || typeof item !== 'object') {
        continue
      }
      const typed = item as Record<string, unknown>
      const address = typeof typed.address === 'string' ? typed.address : ''
      const relation = typeof typed.relation === 'string' ? typed.relation : 'reference'
      const key = `${address}|${relation}|${Number(typed.depth || 0)}`
      if (!address || seen.has(key)) {
        continue
      }
      seen.add(key)
      normalized.push({
        function: typeof typed.function === 'string' ? typed.function : 'unknown',
        address,
        depth: Number(typed.depth || 0),
        relation,
        reference_types: this.normalizeStringArray(typed.reference_types),
        reference_addresses: this.normalizeStringArray(typed.reference_addresses),
        matched_values: this.normalizeStringArray(typed.matched_values),
      })
    }

    return normalized
  }

  private normalizeCrossReferenceAnalysis(raw: unknown): CrossReferenceAnalysis {
    const typed = raw as Record<string, unknown>
    const targetRecord =
      typed.target && typeof typed.target === 'object'
        ? (typed.target as Record<string, unknown>)
        : {}

    const targetType =
      typed.target_type === 'function' ||
      typed.target_type === 'api' ||
      typed.target_type === 'string' ||
      typed.target_type === 'data'
        ? typed.target_type
        : 'function'

    const limitsRecord =
      typed.limits && typeof typed.limits === 'object'
        ? (typed.limits as Record<string, unknown>)
        : {}

    return {
      target_type: targetType,
      target: {
        query: typeof targetRecord.query === 'string' ? targetRecord.query : '',
        resolved_address:
          typeof targetRecord.resolved_address === 'string'
            ? targetRecord.resolved_address
            : undefined,
        resolved_name:
          typeof targetRecord.resolved_name === 'string'
            ? targetRecord.resolved_name
            : undefined,
      },
      inbound: this.normalizeCrossReferenceNodes(typed.inbound),
      outbound: this.normalizeCrossReferenceNodes(typed.outbound),
      direct_xrefs: this.normalizeCrossReferences(typed.direct_xrefs),
      truncated: Boolean(typed.truncated),
      limits: {
        depth: Number(limitsRecord.depth || 1),
        limit: Number(limitsRecord.limit || 20),
      },
    }
  }

  private normalizeGhidraFunction(raw: unknown): GhidraFunction | null {
    if (!raw || typeof raw !== 'object') {
      return null;
    }

    const typed = raw as Record<string, unknown>;
    const callers = this.normalizeNamedAddressList(typed.callers);
    const callees = this.normalizeNamedAddressList(typed.callees);
    const callerRelationships = this.normalizeFunctionRelationships(typed.caller_relationships);
    const calleeRelationships = this.normalizeFunctionRelationships(typed.callee_relationships);

    if (typeof typed.address !== 'string' || typeof typed.name !== 'string') {
      return null;
    }

    return {
      address: typed.address,
      name: typed.name,
      size: Number(typed.size || 0),
      is_thunk: Boolean(typed.is_thunk),
      is_external: Boolean(typed.is_external),
      calling_convention:
        typeof typed.calling_convention === 'string' ? typed.calling_convention : 'unknown',
      signature: typeof typed.signature === 'string' ? typed.signature : '',
      callers,
      caller_count: Number(typed.caller_count || callers.length || callerRelationships.length || 0),
      callees,
      callee_count: Number(typed.callee_count || callees.length || calleeRelationships.length || 0),
      caller_relationships: callerRelationships.length > 0 ? callerRelationships : undefined,
      callee_relationships: calleeRelationships.length > 0 ? calleeRelationships : undefined,
      is_entry_point: Boolean(typed.is_entry_point),
      is_exported: Boolean(typed.is_exported),
    };
  }

  private normalizeDecompiledFunction(raw: unknown): DecompiledFunction {
    const typed = raw as Record<string, unknown>;
    const callers = this.normalizeNamedAddressList(typed.callers);
    const callees = this.normalizeNamedAddressList(typed.callees);
    const callerRelationships = this.normalizeFunctionRelationships(typed.caller_relationships);
    const calleeRelationships = this.normalizeFunctionRelationships(typed.callee_relationships);
    const xrefs = this.normalizeCrossReferences(typed.xrefs);

    return {
      function: typeof typed.function === 'string' ? typed.function : 'unknown',
      address: typeof typed.address === 'string' ? typed.address : '',
      pseudocode: typeof typed.pseudocode === 'string' ? typed.pseudocode : '',
      callers,
      callees,
      caller_relationships: callerRelationships.length > 0 ? callerRelationships : undefined,
      callee_relationships: calleeRelationships.length > 0 ? calleeRelationships : undefined,
      xrefs: xrefs.length > 0 ? xrefs : undefined,
    };
  }

  /**
   * Parse Ghidra output JSON
   * 
   * Requirements: 8.3
   * 
   * @param output - Ghidra stdout output
   * @returns Parsed analysis output
   */
  private parseGhidraOutput(
    output: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): GhidraAnalysisOutput {
    try {
      // Extract JSON from output (Ghidra may output other text before/after JSON)
      const jsonMatch = output.match(/\{[\s\S]*"functions"[\s\S]*\}/);
      if (!jsonMatch) {
        throw new GhidraOutputParseError(
          this.buildNoJsonOutputMessage('ghidra.analyze', output, stderr, diagnostics),
          diagnostics || this.buildSyntheticDiagnostics(output, stderr)
        );
      }

      const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

      // Validate required fields
      if (!parsed.functions || !Array.isArray(parsed.functions)) {
        throw new Error('Invalid Ghidra output: missing functions array');
      }

      const functions = parsed.functions
        .map((item) => this.normalizeGhidraFunction(item))
        .filter((item): item is GhidraFunction => Boolean(item));

      const normalized: GhidraAnalysisOutput = {
        program_name: typeof parsed.program_name === 'string' ? parsed.program_name : 'unknown',
        program_path: typeof parsed.program_path === 'string' ? parsed.program_path : '',
        function_count: Number(parsed.function_count || functions.length),
        functions,
      };

      logger.debug({
        functionCount: normalized.function_count,
        programName: normalized.program_name
      }, 'Parsed Ghidra output');

      return normalized;

    } catch (error) {
      if (error instanceof GhidraOutputParseError) {
        throw error;
      }
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error({
        error: errorMessage,
        outputPreview: output.substring(0, 500),
        stderrPreview: stderr.substring(0, 500),
      }, 'Failed to parse Ghidra output');
      throw new GhidraOutputParseError(
        `Failed to parse Ghidra output: ${errorMessage}`,
        diagnostics || this.buildSyntheticDiagnostics(output, stderr)
      );
    }
  }

  /**
   * Execute DecompileFunction.py script
   * 
   * Requirements: 10.1, 10.2, 10.6 (timeout handling)
   * 
   * @param projectPath - Ghidra project directory path
   * @param projectKey - Unique project key
   * @param samplePath - Path to sample file
   * @param addressOrSymbol - Function address or symbol name
   * @param includeXrefs - Whether to include cross-references
   * @param timeout - Timeout in milliseconds
   * @returns Ghidra output (stdout)
   */
  private async executeDecompileScript(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    addressOrSymbol: string,
    includeXrefs: boolean,
    timeout: number,
    sampleId?: string
  ): Promise<GhidraCommandOutput> {
    const scriptOrder = ['DecompileFunction.java'];
    let lastError: unknown;

    for (const scriptName of scriptOrder) {
      const command = ghidraConfig.analyzeHeadlessPath;
      const logFilePath = sampleId
        ? this.buildGhidraCommandLogPath(sampleId, `decompile_${scriptName}`, projectKey)
        : undefined;
      const ghidraRuntimeLogPath = sampleId
        ? this.buildGhidraRuntimeLogPath(sampleId, `decompile_${scriptName}`, projectKey)
        : undefined;
      const args = [
        projectPath,
        projectKey,
        '-process', path.basename(samplePath),
        '-readOnly',
        '-scriptPath', ghidraConfig.scriptsDir,
        '-postScript', scriptName, addressOrSymbol, String(includeXrefs),
        '-noanalysis',
        ...(ghidraRuntimeLogPath ? ['-log', ghidraRuntimeLogPath] : [])
      ];

      logger.debug({
        command,
        args,
        timeout,
        script: scriptName,
      }, 'Executing function decompilation post-script');

      try {
        return await this.runGhidraCommand(
          command,
          args,
          projectPath,
          timeout,
          undefined,
          `E_TIMEOUT: Function decompilation exceeded timeout of ${timeout}ms`,
          `Function decompilation failed (${scriptName})`,
          logFilePath,
          ghidraRuntimeLogPath
        );
      } catch (error) {
        lastError = error;
        const diagnostics = getGhidraDiagnostics(error);
        logger.warn(
          {
            script: scriptName,
            error: error instanceof Error ? error.message : String(error),
            ghidra_diagnostics: diagnostics,
          },
          'Function decompilation script attempt failed'
        );
      }
    }

    throw lastError instanceof Error
      ? lastError
      : new Error('Function decompilation failed for all configured post-scripts.');
  }

  /**
   * Parse decompile script output
   * 
   * Requirements: 10.3, 10.4, 10.5
   * 
   * @param output - Script stdout output
   * @returns Parsed decompiled function or error
   */
  private parseDecompileOutput(
    output: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): DecompiledFunction | ParsedGhidraError {
    try {
      // Extract JSON from output
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new GhidraOutputParseError(
          this.buildNoJsonOutputMessage('code.function.decompile', output, stderr, diagnostics),
          diagnostics || this.buildSyntheticDiagnostics(output, stderr)
        );
      }

      const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

      // Check for error in the result
      if (parsed.error) {
        return {
          error: typeof parsed.error === 'string' ? parsed.error : String(parsed.error),
          diagnostics: diagnostics || this.buildSyntheticDiagnostics(output, stderr),
        };
      }

      // Validate required fields
      if (!parsed.function || !parsed.address || !parsed.pseudocode) {
        throw new Error('Invalid decompile output: missing required fields');
      }

      const normalized = this.normalizeDecompiledFunction(parsed);

      logger.debug({
        function: normalized.function,
        address: normalized.address,
        pseudocodeLength: normalized.pseudocode.length,
        callerRelationships: normalized.caller_relationships?.length || 0,
        calleeRelationships: normalized.callee_relationships?.length || 0,
      }, 'Parsed decompile output');

      return normalized;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const normalizedDiagnostics =
        diagnostics || getGhidraDiagnostics(error) || this.buildSyntheticDiagnostics(output, stderr)
      logger.error({
        error: errorMessage,
        outputPreview: output.substring(0, 500),
        stderrPreview: stderr.substring(0, 500),
      }, 'Failed to parse decompile output');
      return {
        error: `Failed to parse decompile output: ${errorMessage}`,
        diagnostics: normalizedDiagnostics,
      };
    }
  }

  /**
   * Get control flow graph for a function
   * 
   * Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
   * 
   * @param sampleId - Sample identifier
   * @param addressOrSymbol - Function address (hex string) or symbol name
   * @param timeout - Timeout in milliseconds (default: 30000)
   * @returns Control flow graph with nodes and edges
   */
  async getFunctionCFG(
    sampleId: string,
    addressOrSymbol: string,
    timeout: number = 30000
  ): Promise<ControlFlowGraph> {
    // Check if Ghidra is configured
    if (!ghidraConfig.isValid) {
      throw new Error(
        'Ghidra is not properly configured. Please set GHIDRA_PATH or GHIDRA_INSTALL_DIR environment variable.'
      );
    }

    logger.debug({
      sampleId,
      addressOrSymbol,
      timeout
    }, 'Extracting function CFG');

    // 1. Validate that the sample has been analyzed
    const sample = this.database.findSample(sampleId);
    if (!sample) {
      throw new Error(`Sample not found: ${sampleId}`);
    }

    const resolved = this.resolveGhidraAnalysisForCapability(sampleId, 'cfg');

    // 2. Get workspace and project paths
    await this.workspaceManager.getWorkspace(sampleId);
    const samplePath = await this.resolveSamplePathForSample(sampleId);

    // Verify sample file exists
    if (!fs.existsSync(samplePath)) {
      throw new Error(`Sample file not found: ${samplePath}`);
    }

    // 3. Reuse the Ghidra project from the capability-ready analysis
    const { projectPath, projectKey } = resolved;

    // 4. Execute ExtractCFG.py script
    try {
      const result = await this.runWithProjectLockRetry(
        'Function CFG extraction',
        async () => {
          const output = await this.executeCFGScript(
            projectPath,
            projectKey,
            samplePath,
            addressOrSymbol,
            timeout,
            sampleId
          );

          const parsed = this.parseCFGOutput(output.stdout, output.stderr, output.diagnostics);
          if ('error' in parsed) {
            throw parsed.diagnostics
              ? new GhidraOutputParseError(parsed.error as string, parsed.diagnostics)
              : new Error(parsed.error as string);
          }

          return parsed as ControlFlowGraph;
        },
        {
          sampleId,
          addressOrSymbol,
        }
      );

      logger.info({
        sampleId,
        function: result.function,
        address: result.address,
        nodeCount: result.nodes?.length || 0,
        edgeCount: result.edges?.length || 0
      }, 'Function CFG extracted successfully');

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      logger.error({
        sampleId,
        addressOrSymbol,
        error: errorMessage,
        ghidra_diagnostics: diagnostics
      }, 'Function CFG extraction failed');
      throw error;
    }
  }

  /**
   * Execute ExtractCFG.py script
   * 
   * Requirements: 11.1
   * 
   * @param projectPath - Ghidra project directory path
   * @param projectKey - Unique project key
   * @param samplePath - Path to sample file
   * @param addressOrSymbol - Function address or symbol name
   * @param timeout - Timeout in milliseconds
   * @returns Ghidra output (stdout)
   */
  private async executeCFGScript(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    addressOrSymbol: string,
    timeout: number,
    sampleId?: string
  ): Promise<GhidraCommandOutput> {
    const scriptOrder = ['ExtractCFG.java'];
    let lastError: unknown;

    for (const scriptName of scriptOrder) {
      const command = ghidraConfig.analyzeHeadlessPath;
      const logFilePath = sampleId
        ? this.buildGhidraCommandLogPath(sampleId, `cfg_${scriptName}`, projectKey)
        : undefined;
      const ghidraRuntimeLogPath = sampleId
        ? this.buildGhidraRuntimeLogPath(sampleId, `cfg_${scriptName}`, projectKey)
        : undefined;
      const args = [
        projectPath,
        projectKey,
        '-process', path.basename(samplePath),
        '-readOnly',
        '-scriptPath', ghidraConfig.scriptsDir,
        '-postScript', scriptName, addressOrSymbol,
        '-noanalysis',
        ...(ghidraRuntimeLogPath ? ['-log', ghidraRuntimeLogPath] : [])
      ];

      logger.debug({
        command,
        args,
        timeout,
        script: scriptName,
      }, 'Executing CFG extraction post-script');
      try {
        return await this.runGhidraCommand(
          command,
          args,
          projectPath,
          timeout,
          undefined,
          `E_TIMEOUT: CFG extraction exceeded timeout of ${timeout}ms`,
          `CFG extraction failed (${scriptName})`,
          logFilePath,
          ghidraRuntimeLogPath
        );
      } catch (error) {
        lastError = error;
        const diagnostics = getGhidraDiagnostics(error);
        logger.warn(
          {
            script: scriptName,
            error: error instanceof Error ? error.message : String(error),
            ghidra_diagnostics: diagnostics,
          },
          'CFG extraction script attempt failed'
        );
      }
    }

    throw lastError instanceof Error
      ? lastError
      : new Error('CFG extraction failed for all configured post-scripts.');
  }

  private async searchFunctionsWithGhidra(
    sampleId: string,
    apiQuery: string,
    stringQuery: string,
    limit: number,
    timeout: number
  ): Promise<FunctionSearchResult> {
    const resolved = this.resolveGhidraAnalysisForCapability(sampleId, 'function_index');
    await this.workspaceManager.getWorkspace(sampleId);
    const samplePath = await this.resolveSamplePathForSample(sampleId);

    if (!fs.existsSync(samplePath)) {
      throw new Error(`Sample file not found: ${samplePath}`);
    }

    return this.runWithProjectLockRetry(
      'Function reference search',
      async () => {
        const output = await this.executeSearchScript(
          resolved.projectPath,
          resolved.projectKey,
          samplePath,
          apiQuery,
          stringQuery,
          limit,
          timeout,
          sampleId
        );

        const result = this.parseSearchOutput(output.stdout, output.stderr, output.diagnostics);
        if ('error' in result) {
          throw result.diagnostics
            ? new GhidraOutputParseError(result.error as string, result.diagnostics)
            : new Error(result.error as string);
        }

        return result as FunctionSearchResult;
      },
      {
        sampleId,
        apiQuery,
        stringQuery,
      }
    );
  }

  private searchFunctionsFromIndex(
    sampleId: string,
    apiQuery: string,
    limit: number
  ): FunctionSearchResult {
    const needle = apiQuery.toLowerCase();
    const matches = this.database
      .findFunctions(sampleId)
      .reduce<FunctionSearchMatch[]>((acc, func) => {
        const callees = this.parseFunctionCallees(func.callees);
        const apiMatches = callees.filter((callee) => callee.toLowerCase().includes(needle));
        if (apiMatches.length === 0) {
          return acc;
        }
        acc.push({
          function: func.name || 'unknown',
          address: func.address,
          caller_count: func.caller_count ?? 0,
          callee_count: func.callee_count ?? 0,
          api_matches: apiMatches,
          match_types: ['api_call_index'] as Array<'api_call_index'>,
        });
        return acc;
      }, [])
      .sort((left, right) => {
        const leftScore = (left.api_matches?.length ?? 0) * 10 + left.caller_count;
        const rightScore = (right.api_matches?.length ?? 0) * 10 + right.caller_count;
        return rightScore - leftScore;
      })
      .slice(0, limit);

    return {
      query: {
        api: apiQuery,
        limit,
      },
      matches,
      count: matches.length,
    };
  }

  private parseFunctionCallees(raw: string | null | undefined): string[] {
    if (!raw) {
      return [];
    }

    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed.filter((item): item is string => typeof item === 'string');
    } catch {
      return [];
    }
  }

  private async executeSearchScript(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    apiQuery: string,
    stringQuery: string,
    limit: number,
    timeout: number,
    sampleId?: string
  ): Promise<GhidraCommandOutput> {
    const command = ghidraConfig.analyzeHeadlessPath;
    const logFilePath = sampleId
      ? this.buildGhidraCommandLogPath(sampleId, 'search_function_references', projectKey)
      : undefined;
    const ghidraRuntimeLogPath = sampleId
      ? this.buildGhidraRuntimeLogPath(sampleId, 'search_function_references', projectKey)
      : undefined;
    const args = [
      projectPath,
      projectKey,
      '-process', path.basename(samplePath),
      '-readOnly',
      '-scriptPath', ghidraConfig.scriptsDir,
      '-postScript', 'SearchFunctionReferences.java', apiQuery || '-', stringQuery || '-', String(limit),
      '-noanalysis',
      ...(ghidraRuntimeLogPath ? ['-log', ghidraRuntimeLogPath] : []),
    ];

    logger.debug(
      {
        command,
        args,
        timeout,
      },
      'Executing function reference search post-script'
    );

    return this.runGhidraCommand(
      command,
      args,
      projectPath,
      timeout,
      undefined,
      `E_TIMEOUT: Function search exceeded timeout of ${timeout}ms`,
      'Function search failed',
      logFilePath,
      ghidraRuntimeLogPath
    );
  }

  private async executeCrossReferenceScript(
    projectPath: string,
    projectKey: string,
    samplePath: string,
    targetType: 'function' | 'api' | 'string' | 'data',
    query: string,
    depth: number,
    limit: number,
    timeout: number,
    sampleId?: string
  ): Promise<GhidraCommandOutput> {
    const command = ghidraConfig.analyzeHeadlessPath
    const logFilePath = sampleId
      ? this.buildGhidraCommandLogPath(sampleId, 'analyze_cross_references', projectKey)
      : undefined
    const ghidraRuntimeLogPath = sampleId
      ? this.buildGhidraRuntimeLogPath(sampleId, 'analyze_cross_references', projectKey)
      : undefined
    const args = [
      projectPath,
      projectKey,
      '-process', path.basename(samplePath),
      '-readOnly',
      '-scriptPath', ghidraConfig.scriptsDir,
      '-postScript', 'AnalyzeCrossReferences.java', targetType, query, String(depth), String(limit),
      '-noanalysis',
      ...(ghidraRuntimeLogPath ? ['-log', ghidraRuntimeLogPath] : []),
    ]

    logger.debug(
      {
        command,
        args,
        timeout,
      },
      'Executing cross-reference analysis post-script'
    )

    return this.runGhidraCommand(
      command,
      args,
      projectPath,
      timeout,
      undefined,
      `E_TIMEOUT: Cross-reference analysis exceeded timeout of ${timeout}ms`,
      'Cross-reference analysis failed',
      logFilePath,
      ghidraRuntimeLogPath
    )
  }

  private parseSearchOutput(
    output: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): FunctionSearchResult | ParsedGhidraError {
    try {
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new GhidraOutputParseError(
          this.buildNoJsonOutputMessage('code.functions.search', output, stderr, diagnostics),
          diagnostics || this.buildSyntheticDiagnostics(output, stderr)
        );
      }

      const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
      if (parsed.error) {
        return { error: String(parsed.error) };
      }

      if (!parsed.query || !parsed.matches || !Array.isArray(parsed.matches)) {
        throw new Error('Invalid function search output: missing query or matches');
      }

      const matches: FunctionSearchMatch[] = [];
      for (const rawMatch of parsed.matches) {
        if (!rawMatch || typeof rawMatch !== 'object') {
          continue;
        }

        const match = rawMatch as Record<string, unknown>;
        const apiMatches = Array.isArray(match.api_matches)
          ? match.api_matches.filter((item): item is string => typeof item === 'string')
          : [];

        const stringMatches: FunctionSearchStringMatch[] = [];
        if (Array.isArray(match.string_matches)) {
          for (const item of match.string_matches) {
            if (!item || typeof item !== 'object') {
              continue;
            }
            const typed = item as Record<string, unknown>;
            const value = typeof typed.value === 'string' ? typed.value : '';
            if (!value) {
              continue;
            }
            const normalized: FunctionSearchStringMatch = { value };
            if (typeof typed.data_address === 'string') {
              normalized.data_address = typed.data_address;
            }
            if (typeof typed.referenced_from === 'string') {
              normalized.referenced_from = typed.referenced_from;
            }
            stringMatches.push(normalized);
          }
        }

        const matchTypes = Array.isArray(match.match_types)
          ? match.match_types.filter(
              (
                item
              ): item is 'api_call' | 'string_reference' | 'api_call_index' =>
                item === 'api_call' || item === 'string_reference' || item === 'api_call_index'
            )
          : [];

        const normalizedMatchTypes = Array.from(
          new Set([
            ...matchTypes,
            ...(apiMatches.length > 0 ? ['api_call' as const] : []),
            ...(stringMatches.length > 0 ? ['string_reference' as const] : []),
          ])
        );

        matches.push({
          function: typeof match.function === 'string' ? match.function : 'unknown',
          address: typeof match.address === 'string' ? match.address : '',
          caller_count: Number(match.caller_count || 0),
          callee_count: Number(match.callee_count || 0),
          api_matches: apiMatches,
          string_matches: stringMatches,
          match_types: normalizedMatchTypes,
        });
      }

      const normalizedResult: FunctionSearchResult = {
        query: {
          api:
            typeof (parsed.query as Record<string, unknown>)?.api === 'string'
              ? String((parsed.query as Record<string, unknown>).api)
              : undefined,
          string:
            typeof (parsed.query as Record<string, unknown>)?.string === 'string'
              ? String((parsed.query as Record<string, unknown>).string)
              : undefined,
          limit: Number((parsed.query as Record<string, unknown>)?.limit || matches.length || 0),
        },
        matches,
        count:
          typeof parsed.count === 'number'
            ? parsed.count
            : matches.length,
      };

      return normalizedResult;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const normalizedDiagnostics =
        diagnostics || getGhidraDiagnostics(error) || this.buildSyntheticDiagnostics(output, stderr)
      logger.error(
        {
          error: errorMessage,
          outputPreview: output.substring(0, 500),
          stderrPreview: stderr.substring(0, 500),
        },
        'Failed to parse function search output'
      );
      return {
        error: `Failed to parse function search output: ${errorMessage}`,
        diagnostics: normalizedDiagnostics,
      };
    }
  }

  private parseCrossReferenceOutput(
    output: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): CrossReferenceAnalysis | ParsedGhidraError {
    try {
      const jsonMatch = output.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        throw new GhidraOutputParseError(
          this.buildNoJsonOutputMessage('code.xrefs.analyze', output, stderr, diagnostics),
          diagnostics || this.buildSyntheticDiagnostics(output, stderr)
        )
      }

      const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>
      if (parsed.error) {
        return {
          error: String(parsed.error),
          diagnostics: diagnostics || this.buildSyntheticDiagnostics(output, stderr),
        }
      }

      if (!parsed.target_type || !parsed.target) {
        throw new Error('Invalid cross-reference output: missing target metadata')
      }

      return this.normalizeCrossReferenceAnalysis(parsed)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      const normalizedDiagnostics =
        diagnostics || getGhidraDiagnostics(error) || this.buildSyntheticDiagnostics(output, stderr)
      logger.error(
        {
          error: errorMessage,
          outputPreview: output.substring(0, 500),
          stderrPreview: stderr.substring(0, 500),
        },
        'Failed to parse cross-reference output'
      )
      return {
        error: `Failed to parse cross-reference output: ${errorMessage}`,
        diagnostics: normalizedDiagnostics,
      }
    }
  }

  /**
   * Parse CFG script output
   * 
   * Requirements: 11.2, 11.3, 11.4, 11.5
   * 
   * @param output - Script stdout output
   * @returns Parsed control flow graph or error
   */
  private parseCFGOutput(
    output: string,
    stderr: string,
    diagnostics?: GhidraProcessDiagnostics
  ): ControlFlowGraph | ParsedGhidraError {
    try {
      // Extract JSON from output
      const jsonMatch = output.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new GhidraOutputParseError(
          this.buildNoJsonOutputMessage('code.function.cfg', output, stderr, diagnostics),
          diagnostics || this.buildSyntheticDiagnostics(output, stderr)
        );
      }

      const parsed = JSON.parse(jsonMatch[0]);

      // Check for error in the result
      if (parsed.error) {
        return {
          error: parsed.error,
          diagnostics: diagnostics || this.buildSyntheticDiagnostics(output, stderr),
        };
      }

      // Validate required fields
      if (!parsed.function || !parsed.address || !parsed.nodes || !parsed.edges) {
        throw new Error('Invalid CFG output: missing required fields');
      }

      logger.debug({
        function: parsed.function,
        address: parsed.address,
        nodeCount: parsed.nodes.length,
        edgeCount: parsed.edges.length
      }, 'Parsed CFG output');

      return parsed as ControlFlowGraph;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const normalizedDiagnostics =
        diagnostics || getGhidraDiagnostics(error) || this.buildSyntheticDiagnostics(output, stderr)
      logger.error({
        error: errorMessage,
        outputPreview: output.substring(0, 500),
        stderrPreview: stderr.substring(0, 500),
      }, 'Failed to parse CFG output');
      return {
        error: `Failed to parse CFG output: ${errorMessage}`,
        diagnostics: normalizedDiagnostics,
      };
    }
  }

  /**
   * Store functions to database
   * 
   * Requirements: 8.4
   * 
   * @param sampleId - Sample identifier
   * @param functions - Array of functions from Ghidra
   */
  private async storeFunctions(sampleId: string, functions: GhidraFunction[]): Promise<void> {
    if (functions.length === 0) {
      logger.warn({ sampleId }, 'No functions to store');
      return;
    }

    logger.debug({
      sampleId,
      functionCount: functions.length
    }, 'Storing functions to database');

    // Convert Ghidra functions to database format
    const dbFunctions = functions.map(func => {
      const calleeNames = Array.from(
        new Set([
          ...func.callees.map(c => c.name).filter((name) => typeof name === 'string' && name.length > 0),
          ...(func.callee_relationships || [])
            .map((relationship) => relationship.name)
            .filter((name) => typeof name === 'string' && name.length > 0),
        ])
      );

      return {
      sample_id: sampleId,
      address: func.address,
      name: func.name,
      size: func.size,
      score: 0.0, // Will be calculated by rankFunctions later
      tags: JSON.stringify([]), // Will be populated by rankFunctions
      summary: null,
      caller_count: Math.max(func.caller_count, func.callers.length, func.caller_relationships?.length || 0),
      callee_count: Math.max(func.callee_count, func.callees.length, func.callee_relationships?.length || 0),
      is_entry_point: func.is_entry_point ? 1 : 0,
      is_exported: func.is_exported ? 1 : 0,
      callees: JSON.stringify(calleeNames)
    };
    });

    // Use batch insert for better performance
    this.database.insertFunctionsBatch(dbFunctions);

    logger.info({
      sampleId,
      functionCount: dbFunctions.length
    }, 'Functions stored successfully');
  }

  /**
   * Create a job result from analysis result
   * Helper method for job queue integration
   * 
   * @param analysisResult - Analysis result
   * @param elapsedMs - Elapsed time in milliseconds
   * @returns Job result
   */
  createJobResult(analysisResult: AnalysisResult, elapsedMs: number): JobResult {
    return {
      jobId: analysisResult.analysisId,
      ok: true,
      data: analysisResult,
      errors: [],
      warnings: [],
      artifacts: [],
      metrics: {
        elapsedMs,
        peakRssMb: Math.round(process.memoryUsage().rss / 1024 / 1024 * 100) / 100
      }
    };
  }

  /**
   * Create a job result from error
   * Helper method for job queue integration
   * 
   * @param jobId - Job identifier
   * @param error - Error that occurred
   * @param elapsedMs - Elapsed time in milliseconds
   * @returns Job result
   */
  createErrorJobResult(jobId: string, error: Error, elapsedMs: number): JobResult {
    return {
      jobId,
      ok: false,
      errors: [error.message],
      warnings: [],
      artifacts: [],
      metrics: {
        elapsedMs,
        peakRssMb: 0
      }
    };
  }
}

/**
 * Create a decompiler worker instance
 * 
 * @param database - Database manager
 * @param workspaceManager - Workspace manager
 * @returns Decompiler worker instance
 */
export function createDecompilerWorker(
  database: DatabaseManager,
  workspaceManager: WorkspaceManager
): DecompilerWorker {
  return new DecompilerWorker(database, workspaceManager);
}
