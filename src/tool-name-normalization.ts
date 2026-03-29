import type { ToolDefinition } from './types.js'

const TOOL_NAME_PREFIX_PATTERN =
  /\b(?:sample|workflow|report|task|tool|system|ghidra|graphviz|rizin|yara|yara_x|upx|retdec|angr|qiling|panda|wine|code|analysis|strings|binary|crypto|breakpoint|trace|dynamic|runtime|sandbox|dll|com|pe|compiler|static|rust_binary|dotnet|artifact|artifacts|ioc|attack|llm|packer)(?:\.[A-Za-z0-9_-]+)+\b/g

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
  mappings: ReadonlyArray<readonly [string, string]>
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
        rewriteToolReferencesInValue(item, mappings),
      ])
    ) as T
  }

  return value
}
