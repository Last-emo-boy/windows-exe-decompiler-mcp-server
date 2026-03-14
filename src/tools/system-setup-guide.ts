import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  RequiredUserInputSchema,
  SetupActionSchema,
  buildAllSetupActions,
  buildBaselinePythonSetupActions,
  buildDynamicDependencySetupActions,
  buildGhidraRequiredUserInputs,
  buildGhidraSetupActions,
  buildPyGhidraSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'

const TOOL_NAME = 'system.setup.guide'

export const systemSetupGuideInputSchema = z.object({
  focus: z
    .enum(['all', 'python', 'dynamic', 'ghidra'])
    .default('all')
    .describe('Which setup area to describe. Use all for a first-run bootstrap guide.'),
  include_optional: z
    .boolean()
    .default(true)
    .describe('Include optional setup actions such as PyGhidra and dynamic-analysis extras.'),
})

export const systemSetupGuideOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    focus: z.enum(['all', 'python', 'dynamic', 'ghidra']),
    setup_actions: z.array(SetupActionSchema),
    required_user_inputs: z.array(RequiredUserInputSchema),
    notes: z.array(z.string()),
  }),
  errors: z.array(z.string()).optional(),
})

export const systemSetupGuideToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Explain required bootstrap steps, including pip install commands and user-supplied paths such as GHIDRA_PATH.',
  inputSchema: systemSetupGuideInputSchema,
  outputSchema: systemSetupGuideOutputSchema,
}

export function createSystemSetupGuideHandler() {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = systemSetupGuideInputSchema.parse(args)

    let setupActions = buildAllSetupActions(input.include_optional)
    let requiredUserInputs = buildGhidraRequiredUserInputs()
    const notes = [
      'Prefer absolute paths when providing tool locations such as the Ghidra installation directory.',
      'If your MCP client can read the local filesystem, prefer sample.ingest(path=...) over bytes_b64.',
    ]

    if (input.focus === 'python') {
      setupActions = mergeSetupActions(buildBaselinePythonSetupActions())
      requiredUserInputs = []
    } else if (input.focus === 'dynamic') {
      setupActions = mergeSetupActions(
        buildBaselinePythonSetupActions(),
        input.include_optional ? buildDynamicDependencySetupActions() : []
      )
      requiredUserInputs = []
    } else if (input.focus === 'ghidra') {
      setupActions = mergeSetupActions(
        buildGhidraSetupActions(),
        input.include_optional ? buildPyGhidraSetupActions() : []
      )
      requiredUserInputs = mergeRequiredUserInputs(buildGhidraRequiredUserInputs())
    }

    return {
      ok: true,
      data: {
        focus: input.focus,
        setup_actions: setupActions,
        required_user_inputs: requiredUserInputs,
        notes,
      },
    }
  }
}
