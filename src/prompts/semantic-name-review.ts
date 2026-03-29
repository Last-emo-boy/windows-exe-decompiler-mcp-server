import type { PromptArgs, PromptDefinition, PromptResult } from '../types.js'

export const semanticNameReviewPromptDefinition: PromptDefinition = {
  name: 'reverse.semantic_name_review',
  title: 'Semantic Name Review',
  description:
    'Guide an external LLM to review structured reverse-engineering evidence and return JSON name suggestions.',
  arguments: [
    {
      name: 'prepared_bundle_json',
      description: 'JSON bundle produced by code.function.rename.prepare',
      required: true,
    },
    {
      name: 'analysis_goal',
      description: 'Optional analysis goal to bias the review toward a malware/operator-tooling objective',
      required: false,
    },
  ],
}

export function buildSemanticNameReviewPromptText(
  preparedBundleJson: string,
  analysisGoal?: string
): string {
  const goal =
    analysisGoal?.trim() ||
    'Review the supplied function evidence bundle and propose precise, human-readable semantic names.'

  return [
    goal,
    '',
    'You are reviewing structured reverse-engineering evidence from an MCP server.',
    'Use only the supplied evidence. Do not invent APIs, data structures, or behaviors that are not present in the bundle.',
    '',
    'Naming policy:',
    '- Preserve any existing rule_based_name unless the bundle explicitly marks the function unresolved.',
    '- Prefer snake_case names that describe observable behavior, such as read_remote_memory, write_remote_memory, or parse_pe_sections.',
    '- Return no suggestion when evidence is too weak. Weak evidence is better represented as a lower confidence candidate than as a hallucinated precise name.',
    '- Keep suggestions implementation-agnostic. Avoid compiler, thunk, or framework noise unless it is the dominant behavior.',
    '',
    'Output contract:',
    'Return strict JSON only, with the shape {"suggestions":[...]}',
    'Each suggestion item must contain:',
    '- address_or_function, or separate address / function fields',
    '- candidate_name',
    '- confidence',
    '- why',
    '- required_assumptions',
    '- evidence_used',
    '- If no evidence-grounded rename is justified, return {"suggestions":[]} instead of inventing a precise name.',
    '- Do not wrap the JSON in markdown or prose.',
    '',
    'The client should pass your JSON result to code.function.rename.apply.',
    '',
    'Prepared bundle JSON:',
    preparedBundleJson,
  ].join('\n')
}

export function createSemanticNameReviewPromptHandler() {
  return async (args: PromptArgs): Promise<PromptResult> => ({
    description:
      'Prompt template for evidence-grounded semantic renaming of reconstructed functions.',
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: buildSemanticNameReviewPromptText(
            args.prepared_bundle_json || '',
            args.analysis_goal
          ),
        },
      },
    ],
  })
}
