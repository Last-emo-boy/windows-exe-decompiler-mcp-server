import type { ToolDefinition } from '../types.js'

/**
 * Known tool namespace prefixes.
 * Add entries here instead of editing a regex when new plugins are added.
 */
export const TOOL_NAMESPACES: ReadonlySet<string> = new Set([
  'sample',
  'workflow',
  'report',
  'task',
  'tool',
  'system',
  'ghidra',
  'graphviz',
  'rizin',
  'yara',
  'yara_x',
  'upx',
  'retdec',
  'angr',
  'qiling',
  'panda',
  'wine',
  'code',
  'analysis',
  'strings',
  'binary',
  'crypto',
  'breakpoint',
  'trace',
  'dynamic',
  'runtime',
  'sandbox',
  'dll',
  'com',
  'pe',
  'compiler',
  'static',
  'rust_binary',
  'dotnet',
  'artifact',
  'artifacts',
  'ioc',
  'attack',
  'llm',
  'packer',
])

// Build the regex dynamically from the namespace set (sorted longest-first to avoid partial matches)
const sortedNamespaces = Array.from(TOOL_NAMESPACES).sort((a, b) => b.length - a.length)
const TOOL_NAME_PREFIX_PATTERN = new RegExp(
  `\\b(?:${sortedNamespaces.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?:\\.[A-Za-z0-9_-]+)+\\b`,
  'g'
)

/**
 * Fields that are safe to rewrite tool references in.
 * All other fields are left untouched to avoid corrupting
 * base64 data, binary paths, hashes, etc.
 */
const REWRITABLE_FIELDS = new Set([
  'description',
  'text',
  'help',
  'hint',
  'message',
  'summary',
  'instructions',
  'guidance',
  // `content` may contain hash-bound artifact bytes, not tool guidance.
  'output',
  'recommendation',
  'next_steps',
  'analysis_tip',
  'tool_tip',
  'note',
  'notes',
  'error',
  'warning',
  'info',
  'data',
  'metrics',
  'tool',
  'recommended_next_tools',
])

export function toTransportToolName(name: string): string {
  const replaced = name
    .replace(/\./g, '_')
    .replace(/[^A-Za-z0-9_-]/g, '_')
    .replace(/_+/g, '_')

  if (/^[A-Za-z]/.test(replaced)) {
    return replaced
  }

  return `tool_${replaced}`
}

export function getCanonicalToolName(definition: ToolDefinition): string {
  return definition.canonicalName || definition.name
}

export function buildToolNameMappings(canonicalNames: Iterable<string>): Array<[string, string]> {
  return Array.from(new Set(Array.from(canonicalNames)))
    .map((canonicalName) => [canonicalName, toTransportToolName(canonicalName)] as [string, string])
    .filter(([canonicalName, transportName]) => canonicalName !== transportName)
    .sort((left, right) => right[0].length - left[0].length)
}

/** Cached reverse map from transport names back to canonical names. */
let reverseMap: Map<string, string> | null = null
let reverseMapSource: ReadonlyArray<readonly [string, string]> | null = null

/**
 * Resolve a transport-format tool name back to its canonical dotted form.
 * Returns the input unchanged if no mapping exists.
 */
export function fromTransportToolName(
  transportName: string,
  mappings: ReadonlyArray<readonly [string, string]>
): string {
  // Rebuild reverse map only when the mappings reference changes
  if (reverseMapSource !== mappings) {
    reverseMap = new Map(mappings.map(([canonical, transport]) => [transport, canonical]))
    reverseMapSource = mappings
  }
  return reverseMap.get(transportName) ?? transportName
}

export function rewriteToolReferencesInText(
  text: string,
  mappings: ReadonlyArray<readonly [string, string]>
): string {
  let rewritten = text
  for (const [canonicalName, transportName] of mappings) {
    rewritten = rewritten.split(canonicalName).join(transportName)
  }
  rewritten = rewritten.replace(TOOL_NAME_PREFIX_PATTERN, (match) => toTransportToolName(match))
  return rewritten
}

export function rewriteToolReferencesInValue<T>(
  value: T,
  mappings: ReadonlyArray<readonly [string, string]>,
  _fieldName?: string
): T {
  if (typeof value === 'string') {
    return rewriteToolReferencesInText(value, mappings) as T
  }

  if (Array.isArray(value)) {
    return value.map((item) => rewriteToolReferencesInValue(item, mappings)) as T
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        // Only rewrite whitelisted fields to avoid corrupting data
        REWRITABLE_FIELDS.has(key) ? rewriteToolReferencesInValue(item, mappings, key) : item,
      ])
    ) as T
  }

  return value
}
