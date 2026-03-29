# LLM Tools Migration Guide

## Overview

This guide helps you migrate from the old 3-step LLM tools to the new unified `llm.analyze` interface.

## What's Changing

### Old API (Deprecated)

The following tools are deprecated and will be removed in a future version:

- `code.function.rename.prepare` → `code.function.rename.review` → `code.function.rename.apply`
- `code.function.explain.prepare` → `code.function.explain.review` → `code.function.explain.apply`
- `code.module.review.prepare` → `code.module.review` → `code.module.review.apply`

**Problems with old API:**
- Requires 3 separate tool calls
- Manual JSON result passing
- No context awareness
- Low adoption rate (<5%)

### New API (Recommended)

Single unified interface: `llm.analyze`

**Benefits:**
- Single tool call handles complete flow
- Automatic context management
- Smart triggering based on confidence/complexity
- Better integration with workflows

## Migration Examples

### Example 1: Function Rename

**Old Way (3 calls):**

```typescript
// Step 1: Prepare
const prepareResult = await code.function.rename.prepare({
  sample_id: 'sha256:abc123',
  address: '0x140001000',
})

// Step 2: Review (manual JSON passing)
const reviewResult = await code.function.rename.review({
  sample_id: 'sha256:abc123',
  review_bundle: prepareResult.data.bundle,
})

// Step 3: Apply
const applyResult = await code.function.rename.apply({
  sample_id: 'sha256:abc123',
  accepted_suggestions: reviewResult.data.suggestions,
})
```

**New Way (1 call):**

```typescript
const result = await llm.analyze({
  sample_id: 'sha256:abc123',
  task: 'review',
  context: 'Function at 0x140001000 needs semantic naming',
  goal: 'Propose precise human-readable semantic names',
  max_tokens: 2000,
  temperature: 0.2,
})

// Result contains LLM response directly
console.log(result.data.response)
```

### Example 2: Function Explanation

**Old Way (3 calls):**

```typescript
// Step 1: Prepare
const prepareResult = await code.function.explain.prepare({
  sample_id: 'sha256:abc123',
  topk: 6,
})

// Step 2: Review
const reviewResult = await code.function.explain.review({
  sample_id: 'sha256:abc123',
  review_bundle: prepareResult.data.bundle,
})

// Step 3: Apply
const applyResult = await code.function.explain.apply({
  sample_id: 'sha256:abc123',
  accepted_explanations: reviewResult.data.explanations,
})
```

**New Way (1 call):**

```typescript
const result = await llm.analyze({
  sample_id: 'sha256:abc123',
  task: 'explain',
  context: 'Explain the top 6 functions by rank',
  goal: 'Explain functions in plain language with evidence-grounded rewrite guidance',
  max_tokens: 2000,
  temperature: 0.2,
})

console.log(result.data.response)
```

### Example 3: Module Review

**Old Way (3 calls):**

```typescript
// Step 1: Prepare
const prepareResult = await code.module.review.prepare({
  sample_id: 'sha256:abc123',
  module_name: 'crypto_module',
})

// Step 2: Review
const reviewResult = await code.module.review({
  sample_id: 'sha256:abc123',
  review_bundle: prepareResult.data.bundle,
})

// Step 3: Apply
const applyResult = await code.module.review.apply({
  sample_id: 'sha256:abc123',
  refined_name: reviewResult.data.refined_name,
  summary: reviewResult.data.summary,
})
```

**New Way (1 call):**

```typescript
const result = await llm.analyze({
  sample_id: 'sha256:abc123',
  task: 'review',
  context: 'Module: crypto_module - handles encryption/decryption operations',
  goal: 'Review and critique module analysis, identify gaps and suggest improvements',
  max_tokens: 2000,
  temperature: 0.2,
})

console.log(result.data.response)
```

## Task Types

The new `llm.analyze` supports 4 task types:

| Task | Use Case | Example |
|------|----------|---------|
| `summarize` | Concise summaries | "Summarize the analysis results" |
| `explain` | Clear explanations | "Explain this function's behavior" |
| `recommend` | Actionable recommendations | "Recommend next analysis steps" |
| `review` | Critical review | "Review and identify gaps" |

## Context Management

The new API automatically manages context:

```typescript
// Context is built automatically from:
// - Analysis goal (triage/reverse/report)
// - User preferences (detail level)
// - History (previous decisions)
// - Sample context (binary type, capabilities)

const result = await llm.analyze({
  sample_id: 'sha256:abc123',
  task: 'explain',
  context: 'Auto-populated from analysis context',
  // No need to manually pass bundle JSON!
})
```

## Smart Triggering

LLM assistance is now automatically triggered when:

- Confidence < 0.6 (low confidence)
- Complexity > 0.8 (high complexity)
- New pattern detected
- User preference: always use LLM

You can still manually call `llm.analyze` anytime.

## Timeline

| Date | Action |
|------|--------|
| Now | New `llm.analyze` available |
| v0.2.0 | Old tools marked deprecated |
| v0.3.0 | Old tools removed (breaking change) |

## FAQ

### Q: Can I still use the old tools?

**A:** Yes, old tools are still available but marked as deprecated. They will be removed in v0.3.0.

### Q: Do I need to configure LLM API keys?

**A:** No! The new API uses your MCP Client's LLM capabilities (Claude Desktop, Cursor, etc.). No additional configuration needed.

### Q: What if my MCP Client doesn't support LLM?

**A:** The tool will return an error suggesting you use an MCP Client with LLM capabilities. Old tools will still work as fallback.

### Q: How do I track LLM token usage?

**A:** Token usage is automatically tracked and logged. Check console logs for `[LLM Usage]` messages.

### Q: Can I customize the LLM temperature?

**A:** Yes, use the `temperature` parameter (0=focused, 1=creative). Default is 0.2 for analysis tasks.

## Support

For migration issues or questions:
- Check documentation: `docs/LLM-INTEGRATION.md`
- Review examples: `docs/LLM-EXAMPLES.md`
- Report issues: GitHub Issues
