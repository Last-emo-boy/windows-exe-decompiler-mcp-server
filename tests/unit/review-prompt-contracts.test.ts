import { describe, test, expect } from '@jest/globals'
import { buildSemanticNameReviewPromptText } from '../../src/prompts/semantic-name-review.js'
import { buildFunctionExplanationReviewPromptText } from '../../src/prompts/function-explanation-review.js'
import { buildModuleReconstructionReviewPromptText } from '../../src/prompts/module-reconstruction-review.js'

describe('review prompt contracts', () => {
  test('semantic naming prompt prefers empty results over hallucinated precision', () => {
    const prompt = buildSemanticNameReviewPromptText('{"functions":[]}', 'Review names.')

    expect(prompt).toContain('{"suggestions":[]}')
    expect(prompt).toContain('Do not wrap the JSON in markdown or prose')
    expect(prompt).toContain('no suggestion')
  })

  test('function explanation prompt preserves uncertainty and avoids speculative rewrites', () => {
    const prompt = buildFunctionExplanationReviewPromptText('{"functions":[]}', 'Explain behavior.')

    expect(prompt).toContain('{"explanations":[]}')
    expect(prompt).toContain('Do not wrap the JSON in markdown or prose')
    expect(prompt).toContain('recovered the original source code')
  })

  test('module reconstruction prompt discourages invented roles and unsupported summaries', () => {
    const prompt = buildModuleReconstructionReviewPromptText('{"modules":[]}', 'Review modules.')

    expect(prompt).toContain('{"reviews":[]}')
    expect(prompt).toContain('Do not wrap the JSON in markdown or prose')
    expect(prompt).toContain('Do not invent exports, APIs, modules, or behaviors')
  })
})
