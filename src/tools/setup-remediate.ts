/**
 * setup.remediate tool - Setup remediation workflow entrypoint
 * Tasks: setup-remediation-loop 1.1, 1.2, 2.1, 2.2
 */

import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createSystemHealthHandler } from './system-health.js'
import { createSystemSetupGuideHandler } from './system-setup-guide.js'

const TOOL_NAME = 'setup.remediate'
const TOOL_VERSION = '0.1.0'

const BlockedToolContextSchema = z.object({
  tool_name: z.string().describe('Name of the blocked tool'),
  sample_id: z.string().optional().describe('Sample ID if applicable'),
  error_message: z.string().optional().describe('Error message that caused the block'),
  setup_required: z.string().optional().describe('Setup requirement identifier'),
  context: z.record(z.unknown()).optional().describe('Additional blocked context'),
})

export const SetupRemediateInputSchema = z.object({
  blocked_tool: BlockedToolContextSchema.describe('Context about the blocked tool that triggered remediation'),
  include_health_check: z.boolean().default(true).describe('Whether to run system.health as part of diagnosis'),
  include_setup_guide: z.boolean().default(true).describe('Whether to include detailed setup guidance'),
  session_tag: z.string().optional().describe('Optional session tag for grouping remediation state'),
})

export const SetupActionSchema = z.object({
  action_type: z.enum(['pip_install', 'set_env_var', 'install_package', 'run_command', 'manual_step']),
  command: z.string().optional().describe('Exact command to run'),
  description: z.string().describe('Human-readable description of the action'),
  required: z.boolean().default(true),
  platform: z.enum(['all', 'windows', 'linux', 'macos']).default('all'),
})

export const RequiredUserInputSchema = z.object({
  input_name: z.string().describe('Name of the required input (e.g., GHIDRA_PATH)'),
  description: z.string().describe('What this input is for'),
  example_value: z.string().optional().describe('Example value'),
  validation_pattern: z.string().optional().describe('Optional regex pattern for validation'),
})

export const RetryGuidanceSchema = z.object({
  retry_tool: z.string().describe('Tool to retry after remediation'),
  retry_conditions: z.array(z.string()).describe('Conditions that must be met before retry'),
  resume_target: z.string().describe('Original analysis step to resume'),
  estimated_setup_time_sec: z.number().optional().describe('Estimated time to complete setup'),
})

export const SetupRemediateDataSchema = z.object({
  status: z.enum(['diagnosed', 'setup_required', 'manual_only', 'retry_ready']),
  diagnosis_summary: z.string().describe('Compact human-readable summary of the diagnosis'),
  blocked_tool: BlockedToolContextSchema,
  root_cause: z.string().describe('Identified root cause of the block'),
  setup_actions: z.array(SetupActionSchema).describe('Machine-readable setup actions'),
  required_user_inputs: z.array(RequiredUserInputSchema).describe('Required user-provided inputs'),
  retry_guidance: RetryGuidanceSchema.describe('How to resume the original analysis after setup'),
  health_check: z.any().optional().describe('Optional system.health result if include_health_check=true'),
  setup_guide: z.any().optional().describe('Optional system.setup.guide result if include_setup_guide=true'),
})

export const SetupRemediateOutputSchema = z.object({
  ok: z.boolean(),
  data: SetupRemediateDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type SetupRemediateInput = z.infer<typeof SetupRemediateInputSchema>
export type SetupRemediateData = z.infer<typeof SetupRemediateDataSchema>

export const setupRemediateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Setup remediation workflow that diagnoses blocked tools and returns machine-readable recovery guidance. ' +
    'Use this when a tool returns setup_required or when system.health reports degraded components. ' +
    'This workflow orchestrates diagnosis, setup guidance, and retry sequencing so AI clients can recover from environment issues without manual guesswork. ' +
    '\n\nDecision guide:\n' +
    '- Use when: A tool failed with setup_required, or you need to diagnose environment issues before retrying.\n' +
    '- Do not use when: The error is not environment-related (e.g., sample not found).\n' +
    '- Typical next step: Follow setup_actions, provide required_user_inputs, then retry the blocked tool.\n' +
    '- Common mistake: Retrying the blocked tool immediately without completing setup actions first.',
  inputSchema: SetupRemediateInputSchema,
  outputSchema: SetupRemediateOutputSchema,
}

interface SetupRemediateDependencies {
  healthHandler?: (args: ToolArgs) => Promise<WorkerResult>
  setupGuideHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

export function createSetupRemediateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  deps: SetupRemediateDependencies = {}
) {
  const healthHandler = deps.healthHandler || (() => Promise.resolve({ ok: true, data: {} } as WorkerResult))
  const setupGuideHandler = deps.setupGuideHandler || (() => Promise.resolve({ ok: true, data: {} } as WorkerResult))

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = SetupRemediateInputSchema.parse(args)

      // Extract blocked tool info
      const blockedTool = input.blocked_tool
      const setupRequired = blockedTool.setup_required || 'unknown'

      // Run health check if requested
      let healthResult: WorkerResult | null = null
      if (input.include_health_check) {
        healthResult = await healthHandler({
          sample_id: blockedTool.sample_id,
          include_ghidra: true,
          include_static_worker: true,
          include_cache_probe: true,
          timeout_ms: 10000,
        })
        warnings.push(...(healthResult.warnings || []))
      }

      // Run setup guide if requested
      let setupGuideResult: WorkerResult | null = null
      if (input.include_setup_guide) {
        setupGuideResult = await setupGuideHandler({
          focus: 'all',
          include_optional: true,
        })
        warnings.push(...(setupGuideResult.warnings || []))
      }

      // Diagnose root cause from blocked tool context
      const rootCause = diagnoseRootCause(blockedTool, healthResult?.data)

      // Build setup actions from diagnosis
      const setupActions = buildSetupActions(rootCause, setupGuideResult?.data)

      // Build required user inputs
      const requiredInputs = buildRequiredUserInputs(rootCause, setupGuideResult?.data)

      // Build retry guidance
      const retryGuidance: z.infer<typeof RetryGuidanceSchema> = {
        retry_tool: blockedTool.tool_name,
        retry_conditions: setupActions.map(a => a.description),
        resume_target: `${blockedTool.tool_name} with original parameters`,
        estimated_setup_time_sec: estimateSetupTime(setupActions),
      }

      // Determine status
      const status = setupActions.length === 0
        ? 'retry_ready'
        : setupActions.some(a => a.action_type === 'manual_step')
          ? 'manual_only'
          : 'setup_required'

      const data: SetupRemediateData = {
        status,
        diagnosis_summary: buildDiagnosisSummary(rootCause, setupActions),
        blocked_tool: blockedTool,
        root_cause: rootCause,
        setup_actions: setupActions,
        required_user_inputs: requiredInputs,
        retry_guidance: retryGuidance,
        ...(healthResult?.data ? { health_check: healthResult.data } : {}),
        ...(setupGuideResult?.data ? { setup_guide: setupGuideResult.data } : {}),
      }

      return {
        ok: true,
        data,
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

function diagnoseRootCause(
  blockedTool: z.infer<typeof BlockedToolContextSchema>,
  healthData?: unknown
): string {
  const error = blockedTool.error_message?.toLowerCase() || ''
  const setupRequired = blockedTool.setup_required || ''

  // Check for common patterns
  if (setupRequired.includes('ghidra') || error.includes('ghidra')) {
    return 'Ghidra environment is not configured or not accessible'
  }
  if (setupRequired.includes('java') || error.includes('java')) {
    return 'Java runtime is missing or not in PATH'
  }
  if (setupRequired.includes('python') || error.includes('python')) {
    return 'Python dependencies are missing or incompatible'
  }
  if (setupRequired.includes('docker') || error.includes('docker')) {
    return 'Docker backend is not available or not running'
  }
  if (error.includes('not found') || error.includes('no such file')) {
    return 'Required file or tool not found'
  }
  if (error.includes('permission') || error.includes('access')) {
    return 'Permission or access control issue'
  }

  return `Blocked by setup requirement: ${setupRequired || 'unknown'}`
}

function buildSetupActions(
  rootCause: string,
  setupGuideData?: unknown
): z.infer<typeof SetupActionSchema>[] {
  const actions: z.infer<typeof SetupActionSchema>[] = []

  if (rootCause.includes('Ghidra')) {
    actions.push({
      action_type: 'set_env_var',
      command: 'Set GHIDRA_PATH environment variable',
      description: 'Set GHIDRA_PATH to your Ghidra installation directory',
      required: true,
      platform: 'all',
    })
  }
  if (rootCause.includes('Java')) {
    actions.push({
      action_type: 'install_package',
      command: 'Install Java 11 or later',
      description: 'Install OpenJDK 11 or later and ensure JAVA_HOME is set',
      required: true,
      platform: 'all',
    })
  }
  if (rootCause.includes('Python')) {
    actions.push({
      action_type: 'pip_install',
      command: 'pip install -r requirements.txt',
      description: 'Install Python dependencies from requirements.txt',
      required: true,
      platform: 'all',
    })
  }
  if (rootCause.includes('Docker')) {
    actions.push({
      action_type: 'run_command',
      command: 'docker-compose up -d',
      description: 'Start Docker containers with docker-compose',
      required: true,
      platform: 'all',
    })
  }

  return actions
}

function buildRequiredUserInputs(
  rootCause: string,
  setupGuideData?: unknown
): z.infer<typeof RequiredUserInputSchema>[] {
  const inputs: z.infer<typeof RequiredUserInputSchema>[] = []

  if (rootCause.includes('Ghidra')) {
    inputs.push({
      input_name: 'GHIDRA_PATH',
      description: 'Absolute path to Ghidra installation directory',
      example_value: 'C:\\ghidra_11.0_PUBLIC',
      validation_pattern: '^[a-zA-Z0-9:\\\\/_-]+$',
    })
  }
  if (rootCause.includes('Java')) {
    inputs.push({
      input_name: 'JAVA_HOME',
      description: 'Absolute path to Java installation directory',
      example_value: 'C:\\Program Files\\Java\\jdk-17',
    })
  }

  return inputs
}

function buildDiagnosisSummary(
  rootCause: string,
  setupActions: z.infer<typeof SetupActionSchema>[]
): string {
  if (setupActions.length === 0) {
    return 'No setup actions required. The blocked tool may be ready to retry.'
  }

  return `Diagnosed: ${rootCause}. Complete ${setupActions.length} setup action(s) before retrying.`
}

function estimateSetupTime(actions: z.infer<typeof SetupActionSchema>[]): number {
  const timePerAction = {
    pip_install: 60,
    set_env_var: 30,
    install_package: 120,
    run_command: 30,
    manual_step: 300,
  }

  return actions.reduce((total, action) => {
    return total + (timePerAction[action.action_type] || 60)
  }, 0)
}
