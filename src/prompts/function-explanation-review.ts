import type { PromptArgs, PromptDefinition, PromptResult } from '../types.js'

export const functionExplanationReviewPromptDefinition: PromptDefinition = {
  name: 'reverse.function_explanation_review',
  title: 'Function Explanation Review',
  description:
    'Guide an external LLM to explain structured reverse-engineering evidence and return strict JSON explanations grounded in MCP evidence.',
  arguments: [
    {
      name: 'prepared_bundle_json',
      description: 'JSON bundle produced by code.function.explain.prepare',
      required: true,
    },
    {
      name: 'analysis_goal',
      description: 'Optional analysis goal to bias the explanation toward malware, tooling, or library semantics',
      required: false,
    },
  ],
}

export function buildFunctionExplanationReviewPromptText(
  preparedBundleJson: string,
  analysisGoal?: string
): string {
  const goal =
    analysisGoal?.trim() ||
    'Explain the supplied functions in plain language and propose evidence-grounded rewrite guidance.'

  return [
    goal,
    '',
    'You are reviewing structured reverse-engineering evidence from an MCP server.',
    'Use only the supplied evidence bundle. Do not invent APIs, data structures, or behaviors that do not appear in the evidence.',
    '',
    'Explanation policy:',
    '- Prefer behavior-first summaries such as "resolves dynamic imports", "dispatches exported commands", or "checks service control state".',
    '- Treat all confidence values as heuristic evidence strength, not calibrated probability.',
    '- Explicitly preserve uncertainty. If a behavior depends on an assumption, state the assumption rather than overstating certainty.',
    '- Keep rewrite guidance implementation-oriented but evidence-grounded. Avoid pretending you recovered the original source code.',
    '',
    'Output contract:',
    'Return strict JSON only, with the shape {"explanations":[...]}',
    'Each explanation item must contain:',
    '- address_or_function, or separate address / function fields',
    '- summary',
    '- behavior',
    '- confidence',
    '- assumptions',
    '- evidence_used',
    '- rewrite_guidance',
    '- If no explanation is evidence-grounded, return {"explanations":[]} instead of filling speculative content.',
    '- Do not wrap the JSON in markdown or prose.',
    '',
    'The client can use your JSON output as a post-processing explanation layer over reconstruct/export results.',
    '',
    'Prepared bundle JSON:',
    preparedBundleJson,
  ].join('\n')
}

export function createFunctionExplanationReviewPromptHandler() {
  return async (args: PromptArgs): Promise<PromptResult> => ({
    description:
      'Prompt template for evidence-grounded function explanation and rewrite guidance.',
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: buildFunctionExplanationReviewPromptText(
            args.prepared_bundle_json || '',
            args.analysis_goal
          ),
        },
      },
    ],
  })
}
