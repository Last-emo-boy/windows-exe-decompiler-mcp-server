import type { PromptArgs, PromptDefinition, PromptResult } from '../types.js'

export const moduleReconstructionReviewPromptDefinition: PromptDefinition = {
  name: 'reverse.module_reconstruction_review',
  title: 'Module Reconstruction Review',
  description:
    'Guide an external LLM to review reconstructed modules and return strict JSON summaries, role hints, and rewrite guidance grounded in MCP evidence.',
  arguments: [
    {
      name: 'prepared_bundle_json',
      description: 'JSON bundle produced by code.module.review.prepare',
      required: true,
    },
    {
      name: 'analysis_goal',
      description: 'Optional analysis goal to bias the review toward tooling, malware, library, or plugin semantics',
      required: false,
    },
  ],
}

export function buildModuleReconstructionReviewPromptText(
  preparedBundleJson: string,
  analysisGoal?: string
): string {
  const goal =
    analysisGoal?.trim() ||
    'Review the reconstructed modules, summarize their likely role, and propose evidence-grounded rewrite guidance.'

  return [
    goal,
    '',
    'You are reviewing module-level reverse-engineering evidence from an MCP server.',
    'Use only the supplied evidence bundle. Do not invent exports, APIs, modules, or behaviors that do not appear in the evidence.',
    '',
    'Review policy:',
    '- Treat all confidence values as heuristic evidence strength, not calibrated probability.',
    '- Prefer module-level roles such as "export dispatch", "COM activation", "DLL lifecycle", or "remote process operations".',
    '- Preserve uncertainty explicitly when a module grouping may contain mixed responsibilities.',
    '- Keep rewrite guidance implementation-oriented and evidence-grounded. Do not pretend you recovered the original source code.',
    '',
    'Output contract:',
    'Return strict JSON only, with the shape {"reviews":[...]}',
    'Each review item must contain:',
    '- module_name',
    '- summary',
    '- role_hint',
    '- confidence',
    '- assumptions',
    '- evidence_used',
    '- rewrite_guidance',
    '- optional refined_name',
    '- optional focus_areas',
    '- optional priority_functions',
    '- If no module-level review is evidence-grounded, return {"reviews":[]} instead of inventing roles or summaries.',
    '- Do not wrap the JSON in markdown or prose.',
    '',
    'Prepared bundle JSON:',
    preparedBundleJson,
  ].join('\n')
}

export function createModuleReconstructionReviewPromptHandler() {
  return async (args: PromptArgs): Promise<PromptResult> => ({
    description:
      'Prompt template for evidence-grounded module review, role refinement, and rewrite guidance.',
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: buildModuleReconstructionReviewPromptText(
            args.prepared_bundle_json || '',
            args.analysis_goal
          ),
        },
      },
    ],
  })
}
