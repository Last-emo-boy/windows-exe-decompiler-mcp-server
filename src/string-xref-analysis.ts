import { z } from 'zod'

const IOC_CATEGORY_ORDER = [
  'suspicious_api',
  'command',
  'url',
  'network',
  'registry',
  'file_path',
  'ipc',
  'config_like',
] as const

const RUST_RUNTIME_PATTERNS = [
  /\bcore::/i,
  /\bstd::/i,
  /\balloc::/i,
  /\brust_begin_unwind\b/i,
  /\brust_panic\b/i,
  /\bpanic_fmt\b/i,
  /\bbacktrace\b/i,
  /\b__rust\b/i,
  /\b(tokio|serde|hyper|reqwest|windows-sys|winapi|ntapi|mio|futures)\b/i,
  /\bcargo\\registry\\src\\/i,
  /\\src\\(main|lib)\.rs\b/i,
  /\brustc\b/i,
]

const GENERIC_RUNTIME_PATTERNS = [
  /\bapi-ms-win-/i,
  /\bvcruntime\d+/i,
  /\bmsvcp\d+/i,
  /\bcrt\b/i,
  /\bexception\b/i,
]

const CONFIG_LIKE_PATTERNS = [
  /\b[a-z0-9_.-]{2,32}\s*[:=]\s*[^\s].+/i,
  /\b(?:mutex|campaign|version|build|profile|server|port|domain|token|key|secret|pipe|service)\b/i,
]

const SUSPICIOUS_API_REGEX =
  /\b(CreateProcess\w*|OpenProcess|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread|VirtualAlloc\w*|LoadLibrary\w*|GetProcAddress|SetWindowsHookEx\w*|RegSetValue\w*|RegCreateKey\w*|Internet(Open|Connect)|Http(OpenRequest|SendRequest)|URLDownloadToFile\w*|WinExec|ShellExecute\w*)\b/g

const BASE64ISH_REGEX = /^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const HEXISH_REGEX = /^(?:0x)?[0-9a-f]{16,}$/i

export const EnrichedStringSourceSchema = z.object({
  source: z.enum(['extract', 'floss']),
  encoding: z.string().nullable().optional(),
  decode_method: z.string().nullable().optional(),
  source_type: z.string().nullable().optional(),
})

export const StringFunctionReferenceSchema = z.object({
  address: z.string(),
  name: z.string().nullable().optional(),
  relation: z.string(),
  depth: z.number().int().nonnegative().optional(),
  confidence: z.number().min(0).max(1).optional(),
})

export const EnrichedStringRecordSchema = z.object({
  value: z.string(),
  normalized_value: z.string(),
  primary_offset: z.number().int(),
  categories: z.array(z.string()),
  labels: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  score: z.number(),
  rationale: z.array(z.string()),
  sources: z.array(EnrichedStringSourceSchema),
  function_refs: z.array(StringFunctionReferenceSchema).optional(),
})

export const EnrichedStringHighlightSchema = z.object({
  value: z.string(),
  offset: z.number().int(),
  categories: z.array(z.string()),
  labels: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  score: z.number(),
  source_labels: z.array(z.string()),
})

export const EnrichedStringBundleSchema = z.object({
  status: z.enum(['ready', 'partial']),
  total_records: z.number().int().nonnegative(),
  kept_records: z.number().int().nonnegative(),
  analyst_relevant_count: z.number().int().nonnegative(),
  runtime_noise_count: z.number().int().nonnegative(),
  encoded_candidate_count: z.number().int().nonnegative(),
  merged_sources: z.boolean(),
  truncated: z.boolean(),
  records: z.array(EnrichedStringRecordSchema),
  top_suspicious: z.array(EnrichedStringHighlightSchema),
  top_iocs: z.array(EnrichedStringHighlightSchema),
  top_runtime_noise: z.array(EnrichedStringHighlightSchema),
  top_decoded: z.array(EnrichedStringHighlightSchema),
  context_windows: z.array(z.any()).optional(),
})

export const XrefFunctionNodeSchema = z.object({
  function: z.string(),
  address: z.string(),
  depth: z.number().int().nonnegative(),
  relation: z.string(),
  reference_types: z.array(z.string()),
  reference_addresses: z.array(z.string()),
  matched_values: z.array(z.string()),
})

export const FunctionContextSummarySchema = z.object({
  function: z.string(),
  address: z.string(),
  score: z.number(),
  top_strings: z.array(z.string()),
  top_categories: z.array(z.string()),
  sensitive_apis: z.array(z.string()),
  inbound_refs: z.array(z.string()),
  outbound_refs: z.array(z.string()),
  rationale: z.array(z.string()),
})

export type EnrichedStringSource = z.infer<typeof EnrichedStringSourceSchema>
export type EnrichedStringRecord = z.infer<typeof EnrichedStringRecordSchema>
export type EnrichedStringBundle = z.infer<typeof EnrichedStringBundleSchema>
export type XrefFunctionNode = z.infer<typeof XrefFunctionNodeSchema>
export type FunctionContextSummary = z.infer<typeof FunctionContextSummarySchema>

export interface ExtractedStringRecordInput {
  offset?: number
  string: string
  encoding?: string | null
}

export interface DecodedStringRecordInput {
  offset?: number
  string: string
  type?: string | null
  decoding_method?: string | null
}

interface BaseRecordInput {
  offset: number
  value: string
  sources: EnrichedStringSource[]
}

export interface BuildEnrichedStringBundleOptions {
  maxRecords?: number
  maxHighlights?: number
  contextWindows?: unknown[]
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function normalizeStringValue(value: string): string {
  return value.replace(/\s+/g, ' ').trim()
}

function buildStringKey(value: string): string {
  return normalizeStringValue(value).toLowerCase()
}

function classifyBaseCategories(value: string): string[] {
  const categories = new Set<string>()
  const lower = value.toLowerCase()

  if (/https?:\/\/[^\s]+/i.test(value)) {
    categories.add('url')
  }
  if (/(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)/.test(value)) {
    categories.add('network')
  }
  if (/\\\\\.\\|\\\\pipe\\|namedpipe/i.test(value)) {
    categories.add('ipc')
  }
  if (/hkey_(local_machine|current_user|classes_root|users|current_config)\\/i.test(lower)) {
    categories.add('registry')
  }
  if (/[a-zA-Z]:\\[^\s]+/.test(value) || /\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+){2,}/.test(value)) {
    categories.add('file_path')
  }
  if (/\b(cmd|powershell|wscript|cscript|rundll32|regsvr32)\.exe\b/i.test(lower)) {
    categories.add('command')
  }
  if (SUSPICIOUS_API_REGEX.test(value)) {
    categories.add('suspicious_api')
  }
  SUSPICIOUS_API_REGEX.lastIndex = 0
  if (CONFIG_LIKE_PATTERNS.some((pattern) => pattern.test(value))) {
    categories.add('config_like')
  }

  return Array.from(categories)
}

function classifyLabels(
  value: string,
  categories: string[],
  sources: EnrichedStringSource[]
): { labels: string[]; rationale: string[] } {
  const labels = new Set<string>()
  const rationale: string[] = []
  const normalized = normalizeStringValue(value)

  if (RUST_RUNTIME_PATTERNS.some((pattern) => pattern.test(normalized))) {
    labels.add('runtime_noise')
    labels.add('rust_runtime')
    rationale.push('matches Rust/runtime marker')
  } else if (GENERIC_RUNTIME_PATTERNS.some((pattern) => pattern.test(normalized))) {
    labels.add('runtime_noise')
    rationale.push('matches generic runtime marker')
  }

  if (BASE64ISH_REGEX.test(normalized) || HEXISH_REGEX.test(normalized) || /\\x[0-9a-f]{2}/i.test(normalized)) {
    labels.add('encoded_candidate')
    rationale.push('resembles encoded or packed text')
  }

  if (categories.includes('config_like')) {
    labels.add('config_like')
    rationale.push('looks like configuration material')
  }

  if (sources.some((source) => source.source === 'floss')) {
    labels.add('decoded_signal')
    rationale.push('contains FLOSS-decoded evidence')
  }

  if (categories.length > 0 || labels.has('decoded_signal') || labels.has('encoded_candidate')) {
    labels.add('analyst_relevant')
  }

  if (!labels.has('runtime_noise') && /[A-Za-z]{4,}/.test(normalized)) {
    labels.add('business_logic')
  }

  return {
    labels: Array.from(labels),
    rationale: Array.from(new Set(rationale)),
  }
}

function computeConfidence(categories: string[], labels: string[], sources: EnrichedStringSource[]): number {
  let confidence = 0.32
  confidence += Math.min(categories.length * 0.1, 0.25)
  if (labels.includes('runtime_noise')) {
    confidence += 0.14
  }
  if (labels.includes('encoded_candidate')) {
    confidence += 0.14
  }
  if (labels.includes('config_like')) {
    confidence += 0.1
  }
  if (labels.includes('decoded_signal')) {
    confidence += 0.08
  }
  if (labels.includes('analyst_relevant')) {
    confidence += 0.08
  }
  if (sources.length > 1) {
    confidence += 0.05
  }
  return Number(clamp(confidence, 0.2, 0.95).toFixed(2))
}

function computeScore(categories: string[], labels: string[], sources: EnrichedStringSource[], value: string): number {
  let score = categories.length * 9
  if (labels.includes('decoded_signal')) {
    score += 6
  }
  if (labels.includes('encoded_candidate')) {
    score += 5
  }
  if (labels.includes('config_like')) {
    score += 4
  }
  if (labels.includes('runtime_noise')) {
    score -= 6
  } else {
    score += 3
  }
  score += Math.min(Math.floor(normalizeStringValue(value).length / 24), 6)
  score += Math.max(0, sources.length - 1) * 2
  return score
}

function dedupeStrings(values: string[]): string[] {
  return Array.from(
    new Set(
      values
        .map((item) => normalizeStringValue(item))
        .filter((item) => item.length > 0)
    )
  )
}

function buildRecord(input: BaseRecordInput): EnrichedStringRecord {
  const categories = classifyBaseCategories(input.value)
  const { labels, rationale } = classifyLabels(input.value, categories, input.sources)
  const normalized = normalizeStringValue(input.value)
  return {
    value: normalized,
    normalized_value: buildStringKey(normalized),
    primary_offset: input.offset,
    categories,
    labels,
    confidence: computeConfidence(categories, labels, input.sources),
    score: computeScore(categories, labels, input.sources, normalized),
    rationale,
    sources: input.sources,
  }
}

function mergeRecord(left: EnrichedStringRecord, right: EnrichedStringRecord): EnrichedStringRecord {
  const mergedSources = [...left.sources]
  for (const source of right.sources) {
    const exists = mergedSources.some(
      (item) =>
        item.source === source.source &&
        item.encoding === source.encoding &&
        item.decode_method === source.decode_method &&
        item.source_type === source.source_type
    )
    if (!exists) {
      mergedSources.push(source)
    }
  }

  const categories = dedupeStrings([...left.categories, ...right.categories])
  const labels = dedupeStrings([...left.labels, ...right.labels])
  const rationale = dedupeStrings([...left.rationale, ...right.rationale])
  const primary_offset = Math.min(left.primary_offset, right.primary_offset)
  const value = left.value.length >= right.value.length ? left.value : right.value

  return {
    value,
    normalized_value: left.normalized_value,
    primary_offset,
    categories,
    labels,
    confidence: computeConfidence(categories, labels, mergedSources),
    score: computeScore(categories, labels, mergedSources, value),
    rationale,
    sources: mergedSources,
    function_refs: dedupeFunctionRefs([...(left.function_refs || []), ...(right.function_refs || [])]),
  }
}

function dedupeFunctionRefs(values: Array<z.infer<typeof StringFunctionReferenceSchema>>): Array<z.infer<typeof StringFunctionReferenceSchema>> {
  const seen = new Set<string>()
  const ordered: Array<z.infer<typeof StringFunctionReferenceSchema>> = []
  for (const item of values) {
    const key = `${item.address}|${item.name || ''}|${item.relation}|${item.depth || 0}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    ordered.push(item)
  }
  return ordered
}

function buildHighlight(record: EnrichedStringRecord): z.infer<typeof EnrichedStringHighlightSchema> {
  return {
    value: record.value,
    offset: record.primary_offset,
    categories: record.categories,
    labels: record.labels,
    confidence: record.confidence,
    score: record.score,
    source_labels: record.sources.map((source) =>
      source.source === 'floss'
        ? `${source.source}${source.source_type ? `:${source.source_type}` : ''}`
        : `${source.source}${source.encoding ? `:${source.encoding}` : ''}`
    ),
  }
}

function buildFallbackContextWindows(records: EnrichedStringRecord[], maxWindows: number): unknown[] {
  const ordered = [...records]
    .filter((item) => Number.isFinite(item.primary_offset))
    .sort((left, right) => left.primary_offset - right.primary_offset)

  if (ordered.length === 0) {
    return []
  }

  const groups: EnrichedStringRecord[][] = []
  let current: EnrichedStringRecord[] = []
  let lastOffset = -1

  for (const record of ordered) {
    if (current.length === 0) {
      current = [record]
      lastOffset = record.primary_offset
      continue
    }
    if (record.primary_offset - lastOffset <= 1024) {
      current.push(record)
    } else {
      groups.push(current)
      current = [record]
    }
    lastOffset = record.primary_offset
  }

  if (current.length > 0) {
    groups.push(current)
  }

  return groups
    .map((group) => ({
      start_offset: group[0].primary_offset,
      end_offset: group[group.length - 1].primary_offset,
      score: group.reduce((total, item) => total + item.score, 0),
      categories: dedupeStrings(group.flatMap((item) => item.categories)).slice(0, 8),
      strings: group.slice(0, 6).map((item) => ({
        offset: item.primary_offset,
        string: item.value,
        categories: item.categories,
        labels: item.labels,
        confidence: item.confidence,
      })),
    }))
    .sort((left, right) => Number(right.score) - Number(left.score))
    .slice(0, maxWindows)
}

function annotateContextWindows(
  windows: unknown[] | undefined,
  index: Map<string, EnrichedStringRecord>,
  maxWindows = 8
): unknown[] {
  if (!Array.isArray(windows) || windows.length === 0) {
    return buildFallbackContextWindows(Array.from(index.values()), maxWindows)
  }

  return windows.slice(0, maxWindows).map((window) => {
    const raw = window && typeof window === 'object' ? (window as Record<string, unknown>) : {}
    const strings = Array.isArray(raw.strings)
      ? raw.strings.slice(0, 6).map((entry) => {
          const stringEntry =
            entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : {}
          const value = typeof stringEntry.string === 'string' ? stringEntry.string : ''
          const record = index.get(buildStringKey(value))
          return {
            offset: stringEntry.offset ?? record?.primary_offset ?? null,
            string: value,
            categories: record?.categories || (Array.isArray(stringEntry.categories) ? stringEntry.categories : []),
            labels: record?.labels || [],
            confidence: record?.confidence ?? null,
          }
        })
      : []

    const categoryPool = strings.flatMap((item) =>
      Array.isArray(item.categories) ? item.categories.map((value) => String(value)) : []
    )

    return {
      start_offset: raw.start_offset ?? null,
      end_offset: raw.end_offset ?? null,
      score: raw.score ?? null,
      categories: dedupeStrings(categoryPool).slice(0, 8),
      strings,
    }
  })
}

export function buildEnrichedStringBundle(
  extractedStrings: ExtractedStringRecordInput[],
  decodedStrings: DecodedStringRecordInput[] = [],
  options: BuildEnrichedStringBundleOptions = {}
): EnrichedStringBundle {
  const merged = new Map<string, EnrichedStringRecord>()

  const addRecord = (record: EnrichedStringRecord) => {
    const existing = merged.get(record.normalized_value)
    if (existing) {
      merged.set(record.normalized_value, mergeRecord(existing, record))
    } else {
      merged.set(record.normalized_value, record)
    }
  }

  for (const item of extractedStrings) {
    if (!item?.string) {
      continue
    }
    addRecord(
      buildRecord({
        offset: Number(item.offset || 0),
        value: item.string,
        sources: [
          {
            source: 'extract',
            encoding: item.encoding || null,
          },
        ],
      })
    )
  }

  for (const item of decodedStrings) {
    if (!item?.string) {
      continue
    }
    addRecord(
      buildRecord({
        offset: Number(item.offset || 0),
        value: item.string,
        sources: [
          {
            source: 'floss',
            source_type: item.type || null,
            decode_method: item.decoding_method || null,
          },
        ],
      })
    )
  }

  const allRecords = Array.from(merged.values()).sort(
    (left, right) => right.score - left.score || left.primary_offset - right.primary_offset
  )
  const maxRecords = Math.max(1, Math.min(options.maxRecords || 80, 200))
  const maxHighlights = Math.max(1, Math.min(options.maxHighlights || 12, 20))
  const keptRecords = allRecords.slice(0, maxRecords)
  const index = new Map(keptRecords.map((item) => [item.normalized_value, item]))

  const topSuspicious = keptRecords
    .filter(
      (item) =>
        item.categories.some((category) => IOC_CATEGORY_ORDER.includes(category as (typeof IOC_CATEGORY_ORDER)[number])) ||
        item.labels.includes('encoded_candidate')
    )
    .slice(0, maxHighlights)
    .map(buildHighlight)

  const topIocs = keptRecords
    .filter((item) =>
      item.categories.some((category) =>
        ['url', 'network', 'ipc', 'command', 'registry', 'file_path', 'suspicious_api'].includes(category)
      )
    )
    .slice(0, maxHighlights)
    .map(buildHighlight)

  const topRuntimeNoise = keptRecords
    .filter((item) => item.labels.includes('runtime_noise'))
    .slice(0, maxHighlights)
    .map(buildHighlight)

  const topDecoded = keptRecords
    .filter((item) => item.labels.includes('decoded_signal'))
    .slice(0, maxHighlights)
    .map(buildHighlight)

  return {
    status: decodedStrings.length > 0 && extractedStrings.length === 0 ? 'partial' : 'ready',
    total_records: allRecords.length,
    kept_records: keptRecords.length,
    analyst_relevant_count: allRecords.filter((item) => item.labels.includes('analyst_relevant')).length,
    runtime_noise_count: allRecords.filter((item) => item.labels.includes('runtime_noise')).length,
    encoded_candidate_count: allRecords.filter((item) => item.labels.includes('encoded_candidate')).length,
    merged_sources: extractedStrings.length > 0 && decodedStrings.length > 0,
    truncated: allRecords.length > keptRecords.length,
    records: keptRecords,
    top_suspicious: topSuspicious,
    top_iocs: topIocs,
    top_runtime_noise: topRuntimeNoise,
    top_decoded: topDecoded,
    context_windows: annotateContextWindows(options.contextWindows, index),
  }
}

export function attachFunctionReferencesToBundle(
  bundle: EnrichedStringBundle,
  xrefResults: Array<{
    target_type: 'string' | 'data'
    query: string
    inbound: XrefFunctionNode[]
  }>
): EnrichedStringBundle {
  if (!Array.isArray(bundle.records) || bundle.records.length === 0) {
    return bundle
  }

  const recordMap = new Map(bundle.records.map((item) => [item.normalized_value, item]))
  for (const result of xrefResults) {
    const key = buildStringKey(result.query)
    const existing = recordMap.get(key)
    if (!existing) {
      continue
    }

    const functionRefs = dedupeFunctionRefs([
      ...(existing.function_refs || []),
      ...result.inbound.map((item) => ({
        address: item.address,
        name: item.function,
        relation: item.relation,
        depth: item.depth,
        confidence: clamp(0.58 + Math.max(0, 2 - item.depth) * 0.12, 0.45, 0.92),
      })),
    ])

    recordMap.set(key, {
      ...existing,
      function_refs: functionRefs.slice(0, 8),
    })
  }

  const records = bundle.records.map((item) => recordMap.get(item.normalized_value) || item)
  return {
    ...bundle,
    records,
  }
}

export function extractSuspiciousApiCandidates(bundle: EnrichedStringBundle, limit = 6): string[] {
  const matches: string[] = []
  for (const record of bundle.records) {
    if (!record.categories.includes('suspicious_api')) {
      continue
    }
    const values = record.value.match(SUSPICIOUS_API_REGEX) || []
    SUSPICIOUS_API_REGEX.lastIndex = 0
    matches.push(...values)
  }
  return dedupeStrings(matches).slice(0, limit)
}

export function buildFunctionContextSummaries(
  bundle: EnrichedStringBundle,
  results: Array<{
    target_type: 'string' | 'api' | 'data' | 'function'
    query: string
    inbound: XrefFunctionNode[]
    outbound?: XrefFunctionNode[]
  }>,
  options: {
    maxFunctions?: number
    maxStringsPerFunction?: number
  } = {}
): FunctionContextSummary[] {
  const maxFunctions = Math.max(1, Math.min(options.maxFunctions || 8, 20))
  const maxStringsPerFunction = Math.max(1, Math.min(options.maxStringsPerFunction || 4, 10))
  const summaries = new Map<string, FunctionContextSummary>()
  const bundleRecordByKey = new Map(bundle.records.map((item) => [item.normalized_value, item]))

  const ensureSummary = (node: XrefFunctionNode) => {
    const existing = summaries.get(node.address)
    if (existing) {
      return existing
    }
    const summary: FunctionContextSummary = {
      function: node.function,
      address: node.address,
      score: 0,
      top_strings: [],
      top_categories: [],
      sensitive_apis: [],
      inbound_refs: [],
      outbound_refs: [],
      rationale: [],
    }
    summaries.set(node.address, summary)
    return summary
  }

  for (const result of results) {
    const inbound = Array.isArray(result.inbound) ? result.inbound : []
    const outbound = Array.isArray(result.outbound) ? result.outbound : []

    for (const node of inbound) {
      const summary = ensureSummary(node)
      summary.score += 8 - Math.min(node.depth, 4)
      summary.inbound_refs = dedupeStrings([...summary.inbound_refs, ...node.reference_types]).slice(0, 8)
      summary.rationale = dedupeStrings([...summary.rationale, `${result.target_type}:${result.query}`]).slice(0, 10)
      if (result.target_type === 'api') {
        summary.sensitive_apis = dedupeStrings([...summary.sensitive_apis, result.query]).slice(0, 8)
        summary.score += 4
      } else {
        summary.top_strings = dedupeStrings([...summary.top_strings, result.query]).slice(0, maxStringsPerFunction)
      }
      const bundleRecord = bundleRecordByKey.get(buildStringKey(result.query))
      if (bundleRecord) {
        summary.top_categories = dedupeStrings([...summary.top_categories, ...bundleRecord.categories]).slice(0, 8)
      }
    }

    for (const node of outbound) {
      const summary = ensureSummary(node)
      summary.score += 4 - Math.min(node.depth, 3)
      summary.outbound_refs = dedupeStrings([...summary.outbound_refs, ...node.reference_types]).slice(0, 8)
      summary.rationale = dedupeStrings([...summary.rationale, `outbound:${result.query}`]).slice(0, 10)
    }
  }

  return Array.from(summaries.values())
    .sort((left, right) => right.score - left.score || left.address.localeCompare(right.address))
    .slice(0, maxFunctions)
}

export function compactStringBundleForContext(bundle: EnrichedStringBundle) {
  return {
    status: bundle.status,
    total_records: bundle.total_records,
    kept_records: bundle.kept_records,
    analyst_relevant_count: bundle.analyst_relevant_count,
    runtime_noise_count: bundle.runtime_noise_count,
    encoded_candidate_count: bundle.encoded_candidate_count,
    merged_sources: bundle.merged_sources,
    truncated: bundle.truncated,
    top_suspicious: bundle.top_suspicious.slice(0, 8),
    top_iocs: bundle.top_iocs.slice(0, 8),
    top_runtime_noise: bundle.top_runtime_noise.slice(0, 6),
    top_decoded: bundle.top_decoded.slice(0, 6),
    context_windows: Array.isArray(bundle.context_windows) ? bundle.context_windows.slice(0, 4) : [],
  }
}
