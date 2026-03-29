# Knowledge Base User Guide

## Overview

The Knowledge Base (KB) system enables persistent storage and sharing of function semantics across samples and team members. It reduces redundant LLM calls and builds institutional knowledge.

## Features

- **Function KB**: Store function names, explanations, and behaviors
- **Sample KB**: Link samples to threat intelligence (families, campaigns)
- **Team KB**: Share knowledge across team members with access control
- **LLM Integration**: Automatic KB lookup before LLM review
- **Confidence Scoring**: Auto (0.3-0.5), LLM (0.6-0.8), Human (0.9-1.0)

## Usage

### Function Naming with KB

```typescript
// With KB integration (default)
const result = await workflow.semantic_name_review({
  sample_id: 'sha256:abc123...',
  address: '0x140001000',
  use_kb: true,  // Default: true
  min_confidence: 0.6,  // Minimum confidence for KB suggestions
})

// Result may come from KB if high-confidence match found
if (result.from_kb) {
  console.log('Name from KB:', result.kb_suggestion.name)
} else {
  console.log('Name from LLM:', result.name)
}
```

### Function Explanation with KB

```typescript
const result = await workflow.function_explanation_review({
  sample_id: 'sha256:abc123...',
  address: '0x140001000',
  use_kb: true,
  contribute_after_review: true,  // Contribute to KB after LLM review
})
```

### Search Functions

```typescript
// Search by APIs
const results = searchFunctions(db, {
  apis: ['CryptDecrypt', 'CryptEncrypt'],
  minConfidence: 0.7,
  limit: 10,
})

// Search by behavior
const results = searchFunctions(db, {
  behavior: 'decrypt',
  minConfidence: 0.6,
})

// Search by similarity
const similar = searchFunctionsBySimilarity(db, {
  apis: ['CreateFile', 'WriteFile'],
  strings: ['config'],
}, {
  minOverlap: 0.5,
  limit: 20,
})
```

### Team KB

```typescript
// Create team KB
await createTeamKb(db, {
  teamId: 'team_alpha',
  visibility: 'private',  // or 'shared'
  defaultAccessLevel: 'read',
}, 'user_123')

// Contribute to team KB
const id = await contributeToTeamKb(db, 'user_123', 'team_alpha', {
  address: '0x1000',
  name: 'decrypt_config',
  explanation: '...',
  behavior: 'decrypt_config',
  features: { apis: [...], strings: [...] },
  source: 'llm',
  sampleId: 'sha256:abc',
})

// Search team KB
const results = searchTeamKb(db, 'user_123', 'team_alpha', {
  apis: ['CryptDecrypt'],
})
```

## Data Model

### Function KB Entry

```typescript
{
  id: string
  features: {
    apis: string[]          // Called APIs
    strings: string[]       // Referenced strings
    cfg_shape: string       // CFG hash
    crypto_constants?: string[]  // Crypto constants
  }
  semantics: {
    name: string            // Function name
    explanation: string     // Plain language explanation
    behavior: string        // Behavior label
    confidence: number      // 0-1 confidence score
    source: 'auto' | 'llm' | 'human'
  }
  samples: string[]         // Sample IDs where found
  created_at: string
  updated_at: string
  user_id?: string          // Contributor
  team_id?: string          // Team KB
}
```

### Sample KB Entry

```typescript
{
  id: string
  sample_id: string
  threat_intel: {
    family?: string         // Malware family
    campaign?: string       // Campaign name
    tags: string[]          // Threat tags
    attribution?: string    // Threat actor
  }
  created_at: string
  updated_at: string
  user_id?: string
}
```

## Search Syntax

### Exact Match

Searches for functions with exact API or string matches:

```typescript
searchFunctions(db, {
  apis: ['CryptDecrypt'],  // Exact API match
  strings: ['password'],   // Fuzzy string match
  minConfidence: 0.7,
})
```

### Similarity Search

Finds functions with overlapping features:

```typescript
searchFunctionsBySimilarity(db, {
  apis: ['Api1', 'Api2'],
  strings: ['str1'],
}, {
  minOverlap: 0.5,  // Minimum 50% overlap
  limit: 20,
})
```

### Hash-based Search

Finds exact duplicates by feature hash:

```typescript
const matches = searchFunctionsByHash(db, apiHash, stringHash)
```

## Confidence Scoring

| Source | Score Range | Description |
|--------|-------------|-------------|
| auto   | 0.3-0.5     | Auto-extracted from strings/APIs |
| llm    | 0.6-0.8     | LLM-reviewed |
| human  | 0.9-1.0     | Human-verified |

## Access Control

### Team KB Levels

- **read**: Can search and view entries
- **write**: Can contribute new entries
- **admin**: Can manage team members and settings

### Visibility

- **private**: Only team members can access
- **shared**: Anyone can read, team members can write

## Audit Logging

All KB operations are logged:

```typescript
const logs = getAuditLogForEntry(db, 'function', 'func_123', 50)
// Returns: [{ userId, action, details, createdAt }, ...]
```

## Best Practices

1. **Enable KB by default**: Use `use_kb: true` for faster responses
2. **Set appropriate confidence**: Use `min_confidence: 0.6` for LLM-reviewed entries
3. **Contribute after review**: Set `contribute_after_review: true` to build KB
4. **Use team KBs**: Share knowledge across team members
5. **Verify high-impact functions**: Manually verify critical functions for higher confidence

## Performance

- **Search time**: < 100ms for 1000+ entries
- **Indexing**: Automatic via `kb_index` table
- **Caching**: Consider caching frequent searches

## Migration

To migrate existing analysis artifacts to KB:

```typescript
const stats = await migrateToKnowledgeBase(db)
console.log(`Migrated ${stats.migratedFunctions} functions`)
```

## Troubleshooting

### No KB matches found

- Check `min_confidence` threshold (try lowering to 0.5)
- Verify API names match exactly
- Try similarity search instead of exact match

### Slow search performance

- Ensure indexes are created (`kb_index` table)
- Limit result count with `limit` parameter
- Use specific API filters

### Access denied errors

- Verify user has appropriate access level
- Check team KB visibility settings
- Contact team admin for write access
