import { z } from 'zod'
import type { DynamicTraceSummary } from './dynamic-trace.js'

const CRYPTO_FAMILY_VALUES = [
  'aes',
  'rsa',
  'des',
  'rc4',
  'chacha20',
  'salsa20',
  'hash',
  'windows_cryptoapi',
  'cng',
  'custom',
  'unknown',
] as const

const CONSTANT_KIND_VALUES = [
  'key_material',
  'iv_material',
  'sbox',
  'round_constant',
  'table_constant',
  'kdf_hint',
  'seed',
  'unknown',
] as const

const EVIDENCE_KIND_VALUES = [
  'import',
  'string',
  'decoded_string',
  'constant',
  'xref',
  'dynamic_trace',
  'capability',
  'function_context',
] as const

const BREAKPOINT_KIND_VALUES = ['function_entry', 'function_exit', 'api_call'] as const
const PREDICATE_SOURCE_VALUES = [
  'register',
  'argument',
  'buffer_length',
  'hit_count',
  'module',
  'function',
  'api',
] as const
const PREDICATE_OPERATOR_VALUES = [
  'eq',
  'neq',
  'gt',
  'gte',
  'lt',
  'lte',
  'contains',
  'starts_with',
  'matches',
] as const
const MEMORY_SLICE_SOURCE_VALUES = ['register', 'argument'] as const

export const ArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.record(z.any()).optional(),
})

export const CryptoEvidenceSchema = z.object({
  kind: z.enum(EVIDENCE_KIND_VALUES),
  value: z.string(),
  source_tool: z.string(),
  location: z.string().optional(),
  function: z.string().optional(),
  confidence: z.number().min(0).max(1),
})

export const CryptoConstantCandidateSchema = z.object({
  kind: z.enum(CONSTANT_KIND_VALUES),
  label: z.string(),
  preview: z.string(),
  encoding: z.enum(['ascii', 'hex', 'base64', 'utf16', 'unknown']),
  byte_length: z.number().int().positive().optional(),
  entropy: z.number().min(0).max(8).optional(),
  source: z.enum(['string', 'decoded_string', 'dynamic_trace', 'unknown']),
  location: z.string().optional(),
  function: z.string().optional(),
  rationale: z.array(z.string()),
  truncated: z.boolean().optional(),
  artifact_ref: ArtifactRefSchema.optional(),
})

export const CryptoFindingSchema = z.object({
  algorithm_family: z.enum(CRYPTO_FAMILY_VALUES),
  algorithm_name: z.string(),
  mode: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1),
  function: z.string().nullable().optional(),
  address: z.string().nullable().optional(),
  source_apis: z.array(z.string()),
  evidence: z.array(CryptoEvidenceSchema),
  candidate_constants: z.array(CryptoConstantCandidateSchema),
  dynamic_support: z.boolean(),
  xref_available: z.boolean(),
})

export const BreakpointCandidateSchema = z.object({
  kind: z.enum(BREAKPOINT_KIND_VALUES),
  address: z.string().optional(),
  function: z.string().optional(),
  api: z.string().optional(),
  module: z.string().optional(),
  reason: z.string(),
  confidence: z.number().min(0).max(1),
  context_capture: z.array(z.string()),
  evidence_sources: z.array(z.string()),
  dynamic_support: z.boolean(),
})

export const TracePredicateSchema = z
  .object({
    source: z.enum(PREDICATE_SOURCE_VALUES),
    register: z.string().optional(),
    argument_index: z.number().int().min(0).max(15).optional(),
    operator: z.enum(PREDICATE_OPERATOR_VALUES),
    value: z.union([z.string(), z.number(), z.boolean()]),
  })
  .superRefine((value, ctx) => {
    if (value.source === 'register' && !value.register) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['register'],
        message: 'register is required when source=register',
      })
    }
    if ((value.source === 'argument' || value.source === 'buffer_length') && value.argument_index === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['argument_index'],
        message: 'argument_index is required when source=argument or source=buffer_length',
      })
    }
    if (
      (value.source === 'module' || value.source === 'function' || value.source === 'api') &&
      typeof value.value !== 'string'
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'value must be a string when source=module, function, or api',
      })
    }
  })

export const TraceConditionGroupSchema = z.object({
  logic: z.enum(['all', 'any']).default('all'),
  predicates: z.array(TracePredicateSchema).max(6).default([]),
})

export const TraceMemorySliceSchema = z
  .object({
    source: z.enum(MEMORY_SLICE_SOURCE_VALUES),
    register: z.string().optional(),
    argument_index: z.number().int().min(0).max(15).optional(),
    max_bytes: z.number().int().min(1).max(512).default(128),
    label: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.source === 'register' && !value.register) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['register'],
        message: 'register is required when memory slice source=register',
      })
    }
    if (value.source === 'argument' && value.argument_index === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['argument_index'],
        message: 'argument_index is required when memory slice source=argument',
      })
    }
  })

export const TraceCapturePlanSchema = z.object({
  registers: z.array(z.string()).max(8).default([]),
  arguments: z.array(z.number().int().min(0).max(15)).max(8).default([]),
  include_return_value: z.boolean().default(true),
  stack_bytes: z.number().int().min(0).max(512).default(64),
  memory_slices: z.array(TraceMemorySliceSchema).max(4).default([]),
})

export const NormalizedTracePlanSchema = z.object({
  breakpoint: BreakpointCandidateSchema,
  condition: TraceConditionGroupSchema,
  capture: TraceCapturePlanSchema,
  limits: z.object({
    max_hits: z.number().int().min(1).max(100),
    max_events: z.number().int().min(1).max(500),
    max_memory_bytes: z.number().int().min(0).max(2048),
  }),
  runtime_mapping: z.object({
    recommended_tool: z.enum(['frida.runtime.instrument', 'frida.script.inject']),
    suggested_script_name: z.enum([
      'api_trace',
      'string_decoder',
      'anti_debug_bypass',
      'crypto_finder',
      'file_registry_monitor',
      'default',
    ]),
    ready: z.boolean(),
    rationale: z.string(),
  }),
})

export type CryptoEvidence = z.infer<typeof CryptoEvidenceSchema>
export type CryptoConstantCandidate = z.infer<typeof CryptoConstantCandidateSchema>
export type CryptoFinding = z.infer<typeof CryptoFindingSchema>
export type BreakpointCandidate = z.infer<typeof BreakpointCandidateSchema>
export type TracePredicate = z.infer<typeof TracePredicateSchema>
export type TraceConditionGroup = z.infer<typeof TraceConditionGroupSchema>
export type TraceCapturePlan = z.infer<typeof TraceCapturePlanSchema>
export type NormalizedTracePlan = z.infer<typeof NormalizedTracePlanSchema>
export type CryptoFamilyValue = (typeof CRYPTO_FAMILY_VALUES)[number]

export interface BasicStringRecord {
  value: string
  labels?: string[]
  categories?: string[]
  function_refs?: Array<{ address?: string; name?: string | null }>
}

export interface FunctionContextLike {
  function?: string
  address?: string
  top_strings?: string[]
  sensitive_apis?: string[]
  rationale?: string[]
}

type ConstantKind = (typeof CONSTANT_KIND_VALUES)[number]
type CryptoFamily = (typeof CRYPTO_FAMILY_VALUES)[number]

const AES_SBOX_PREFIXES = ['637c777bf26b6fc53001672bfed7ab76', '637c777bf26b6fc53001672bfed7ab76ca82c97d']
const AES_RCON_PREFIXES = ['01020408102040801b36', '8d01020408102040801b36']

const FAMILY_CATALOG: Array<{
  family: CryptoFamily
  name: string
  stringPatterns: RegExp[]
  apiPatterns: RegExp[]
}> = [
  {
    family: 'aes',
    name: 'AES',
    stringPatterns: [/\baes(?:[-_ ]?(128|192|256))?\b/i, /\baes_?(encrypt|decrypt)\b/i],
    apiPatterns: [/^AES_(set_.*|encrypt|decrypt)$/i],
  },
  {
    family: 'rsa',
    name: 'RSA',
    stringPatterns: [/\brsa\b/i, /\bpkcs#?1\b/i],
    apiPatterns: [/^BCrypt(Encrypt|Decrypt)$/i, /^Crypt(Encrypt|Decrypt)$/i],
  },
  {
    family: 'des',
    name: 'DES',
    stringPatterns: [/\b3des\b/i, /\bdes\b/i],
    apiPatterns: [],
  },
  {
    family: 'rc4',
    name: 'RC4',
    stringPatterns: [/\brc4\b/i, /\barc4\b/i],
    apiPatterns: [],
  },
  {
    family: 'chacha20',
    name: 'ChaCha20',
    stringPatterns: [/\bchacha20\b/i, /expand 32-byte k/i],
    apiPatterns: [],
  },
  {
    family: 'salsa20',
    name: 'Salsa20',
    stringPatterns: [/\bsalsa20\b/i, /expand 16-byte k/i],
    apiPatterns: [],
  },
  {
    family: 'hash',
    name: 'Hash',
    stringPatterns: [/\bsha(1|224|256|384|512)\b/i, /\bmd5\b/i, /\bcrc32\b/i],
    apiPatterns: [],
  },
  {
    family: 'windows_cryptoapi',
    name: 'Windows CryptoAPI',
    stringPatterns: [/crypt(acquirecontext|encrypt|decrypt|genkey|importkey|exportkey)/i],
    apiPatterns: [/^Crypt(AcquireContext|Encrypt|Decrypt|GenKey|ImportKey|ExportKey)/i],
  },
  {
    family: 'cng',
    name: 'Windows CNG',
    stringPatterns: [/bcrypt(encrypt|decrypt|generatesymmetrickey)/i],
    apiPatterns: [/^BCrypt(Encrypt|Decrypt|GenerateSymmetricKey)/i],
  },
]

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value))
}

function dedupeStrings(values: string[]) {
  return Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
}

function normalizeText(value: string) {
  return value.replace(/\s+/g, ' ').trim()
}

function normalizeHexCandidate(value: string) {
  return value.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '').toLowerCase()
}

function previewValue(value: string, maxChars: number) {
  const normalized = normalizeText(value)
  if (normalized.length <= maxChars) {
    return { preview: normalized, truncated: false }
  }
  return {
    preview: `${normalized.slice(0, maxChars)}...[truncated ${normalized.length - maxChars} chars]`,
    truncated: true,
  }
}

function shannonEntropy(text: string): number {
  if (!text) {
    return 0
  }
  const counts = new Map<string, number>()
  for (const char of text) {
    counts.set(char, (counts.get(char) || 0) + 1)
  }
  const length = text.length
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / length
    entropy -= probability * Math.log2(probability)
  }
  return Number(entropy.toFixed(2))
}

function decodeBase64(value: string): Buffer | null {
  try {
    const normalized = value.replace(/\s+/g, '')
    if (!/^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)) {
      return null
    }
    return Buffer.from(normalized, 'base64')
  } catch {
    return null
  }
}

function decodeHex(value: string): Buffer | null {
  try {
    const normalized = normalizeHexCandidate(value)
    if (normalized.length < 16 || normalized.length % 2 !== 0) {
      return null
    }
    return Buffer.from(normalized, 'hex')
  } catch {
    return null
  }
}

function inferConstantCandidate(
  record: BasicStringRecord,
  previewMaxChars: number
): CryptoConstantCandidate | null {
  const value = normalizeText(record.value)
  if (!value) {
    return null
  }

  const lowered = value.toLowerCase()
  const labels = record.labels || []
  const hexCandidate = normalizeHexCandidate(value)
  let kind: ConstantKind | null = null
  let label = 'candidate material'
  let encoding: 'ascii' | 'hex' | 'base64' | 'utf16' | 'unknown' = 'unknown'
  let byteLength: number | undefined
  let entropy: number | undefined
  const rationale: string[] = []

  if (AES_SBOX_PREFIXES.some((prefix) => hexCandidate.startsWith(prefix))) {
    kind = 'sbox'
    label = 'AES S-box'
    encoding = 'hex'
    byteLength = hexCandidate.length / 2
    rationale.push('matches a known AES S-box prefix')
  } else if (AES_RCON_PREFIXES.some((prefix) => hexCandidate.startsWith(prefix))) {
    kind = 'round_constant'
    label = 'AES round constants'
    encoding = 'hex'
    byteLength = hexCandidate.length / 2
    rationale.push('matches a known AES round-constant prefix')
  } else if (/expand 32-byte k/i.test(value)) {
    kind = 'table_constant'
    label = 'ChaCha20 constant'
    encoding = 'ascii'
    byteLength = Buffer.byteLength(value)
    rationale.push('matches the ChaCha20 constant phrase')
  } else if (/expand 16-byte k/i.test(value)) {
    kind = 'table_constant'
    label = 'Salsa20 constant'
    encoding = 'ascii'
    byteLength = Buffer.byteLength(value)
    rationale.push('matches the Salsa20 constant phrase')
  } else if (/\b(pb?kdf2|argon2|scrypt|bcrypt_pbkdf|hkdf)\b/i.test(value)) {
    kind = 'kdf_hint'
    label = 'KDF hint'
    encoding = 'ascii'
    byteLength = Buffer.byteLength(value)
    rationale.push('matches a known key-derivation label')
  } else {
    const decodedHex = decodeHex(value)
    const decodedBase64 = decodeBase64(value)
    const selected = decodedHex || decodedBase64
    if (selected) {
      encoding = decodedHex ? 'hex' : 'base64'
      byteLength = selected.length
      entropy = shannonEntropy(selected.toString('latin1'))
      if (selected.length === 16) {
        kind = 'iv_material'
        label = '16-byte crypto material'
      } else if (selected.length === 24 || selected.length === 32) {
        kind = 'key_material'
        label = `${selected.length}-byte crypto material`
      } else if (selected.length > 32) {
        kind = labels.includes('encoded_candidate') ? 'key_material' : 'unknown'
        label = 'high-entropy encoded material'
      }
      if (kind) {
        rationale.push(`decoded ${encoding} candidate is ${selected.length} bytes`)
        if (typeof entropy === 'number') {
          rationale.push(`entropy ${entropy.toFixed(2)}`)
        }
      }
    }
  }

  if (!kind && (lowered.includes('seed') || lowered.includes('nonce'))) {
    kind = lowered.includes('seed') ? 'seed' : 'iv_material'
    label = lowered.includes('seed') ? 'seed hint' : 'nonce/IV hint'
    encoding = 'ascii'
    byteLength = Buffer.byteLength(value)
    rationale.push('string contains seed or nonce/IV terminology')
  }

  if (!kind) {
    return null
  }

  const location =
    record.function_refs && record.function_refs.length > 0 ? record.function_refs[0]?.address : undefined
  const fn =
    record.function_refs && record.function_refs.length > 0 ? record.function_refs[0]?.name || undefined : undefined
  const preview = previewValue(value, previewMaxChars)

  return {
    kind,
    label,
    preview: preview.preview,
    encoding,
    ...(byteLength ? { byte_length: byteLength } : {}),
    ...(typeof entropy === 'number' ? { entropy } : {}),
    source: labels.includes('decoded_signal') ? 'decoded_string' : 'string',
    ...(location ? { location } : {}),
    ...(fn ? { function: fn } : {}),
    rationale,
    truncated: preview.truncated,
  }
}

export function extractConstantCandidates(
  records: BasicStringRecord[],
  previewMaxChars = 80,
  limit = 20
): CryptoConstantCandidate[] {
  const candidates: CryptoConstantCandidate[] = []
  const seen = new Set<string>()
  for (const record of records) {
    const candidate = inferConstantCandidate(record, previewMaxChars)
    if (!candidate) {
      continue
    }
    const key = `${candidate.kind}:${candidate.preview}:${candidate.location || ''}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    candidates.push(candidate)
    if (candidates.length >= limit) {
      break
    }
  }
  return candidates
}

function detectMode(values: string[]): string | null {
  for (const value of values) {
    if (/\bgcm\b/i.test(value)) return 'GCM'
    if (/\bcbc\b/i.test(value)) return 'CBC'
    if (/\bctr\b/i.test(value)) return 'CTR'
    if (/\becb\b/i.test(value)) return 'ECB'
    if (/\bcfb\b/i.test(value)) return 'CFB'
    if (/\bofb\b/i.test(value)) return 'OFB'
  }
  return null
}

export function normalizeApiName(value: string) {
  return value.replace(/^.*!/, '').replace(/\(.*/, '').trim()
}

export function collectCryptoApiNames(imports: Record<string, string[]> | undefined, dynamicEvidence?: DynamicTraceSummary | null) {
  const apis = new Set<string>()
  if (imports) {
    for (const functions of Object.values(imports)) {
      if (!Array.isArray(functions)) {
        continue
      }
      for (const value of functions) {
        const normalized = normalizeApiName(String(value))
        if (FAMILY_CATALOG.some((item) => item.apiPatterns.some((pattern) => pattern.test(normalized)))) {
          apis.add(normalized)
        }
      }
    }
  }
  for (const value of dynamicEvidence?.observed_apis || []) {
    const normalized = normalizeApiName(value)
    if (FAMILY_CATALOG.some((item) => item.apiPatterns.some((pattern) => pattern.test(normalized)))) {
      apis.add(normalized)
    }
  }
  return [...apis]
}

function scoreFamilies(
  values: string[],
  apis: string[],
  constants: CryptoConstantCandidate[],
  hasCryptoCapability: boolean,
  dynamicApis: string[],
  sourceTool: string,
  fn?: string,
  location?: string
) {
  const families = new Map<
    CryptoFamily,
    { name: string; score: number; evidence: CryptoEvidence[]; sourceApis: Set<string> }
  >()

  function ensureFamily(family: CryptoFamily, name: string) {
    if (!families.has(family)) {
      families.set(family, {
        name,
        score: 0,
        evidence: [],
        sourceApis: new Set<string>(),
      })
    }
    return families.get(family)!
  }

  for (const entry of FAMILY_CATALOG) {
    for (const value of values) {
      if (entry.stringPatterns.some((pattern) => pattern.test(value))) {
        const target = ensureFamily(entry.family, entry.name)
        target.score += 0.24
        target.evidence.push({
          kind: 'string',
          value,
          source_tool: sourceTool,
          ...(location ? { location } : {}),
          ...(fn ? { function: fn } : {}),
          confidence: 0.66,
        })
      }
    }
    for (const api of apis) {
      if (entry.apiPatterns.some((pattern) => pattern.test(api))) {
        const target = ensureFamily(entry.family, entry.name)
        target.score += 0.28
        target.sourceApis.add(api)
        target.evidence.push({
          kind: dynamicApis.includes(api) ? 'dynamic_trace' : 'import',
          value: api,
          source_tool: dynamicApis.includes(api) ? 'dynamic.trace' : 'pe.imports.extract',
          ...(location ? { location } : {}),
          ...(fn ? { function: fn } : {}),
          confidence: dynamicApis.includes(api) ? 0.84 : 0.62,
        })
      }
    }
  }

  for (const candidate of constants) {
    const family: CryptoFamily | null =
      candidate.kind === 'sbox' || candidate.kind === 'round_constant'
        ? 'aes'
        : /chacha/i.test(candidate.label)
          ? 'chacha20'
          : /salsa/i.test(candidate.label)
            ? 'salsa20'
            : null
    if (!family) {
      continue
    }
    const name =
      FAMILY_CATALOG.find((item) => item.family === family)?.name ||
      family.toUpperCase()
    const target = ensureFamily(family, name)
    target.score += 0.3
    target.evidence.push({
      kind: 'constant',
      value: candidate.label,
      source_tool: 'analysis.context.link',
      ...(candidate.location ? { location: candidate.location } : {}),
      ...(candidate.function ? { function: candidate.function } : {}),
      confidence: 0.82,
    })
  }

  if (families.size === 0 && hasCryptoCapability) {
    const target = ensureFamily('custom', 'Custom or opaque cryptography')
    target.score += 0.12
    target.evidence.push({
      kind: 'capability',
      value: 'static capability triage reported cryptography',
      source_tool: 'static.capability.triage',
      ...(location ? { location } : {}),
      ...(fn ? { function: fn } : {}),
      confidence: 0.58,
    })
  }

  return families
}

function constantMatchesFunction(candidate: CryptoConstantCandidate, context: FunctionContextLike) {
  if (candidate.location && context.address && candidate.location === context.address) {
    return true
  }
  if (candidate.function && context.function && candidate.function === context.function) {
    return true
  }
  return false
}

export function buildCryptoFindings(options: {
  functionContexts: FunctionContextLike[]
  stringRecords: BasicStringRecord[]
  imports?: Record<string, string[]>
  dynamicEvidence?: DynamicTraceSummary | null
  hasCryptoCapability?: boolean
  maxFindings?: number
  maxConstantsPerFinding?: number
  xrefAvailable?: boolean
}) {
  const maxFindings = options.maxFindings ?? 8
  const maxConstantsPerFinding = options.maxConstantsPerFinding ?? 4
  const records = options.stringRecords
  const allConstants = extractConstantCandidates(records, 80, 32)
  const importedAndDynamicApis = collectCryptoApiNames(options.imports, options.dynamicEvidence)
  const dynamicApis = dedupeStrings(options.dynamicEvidence?.observed_apis || []).map(normalizeApiName)
  const xrefAvailable = options.xrefAvailable ?? false
  const findings: CryptoFinding[] = []

  for (const context of options.functionContexts) {
    const contextValues = dedupeStrings([
      ...(context.top_strings || []),
      ...(context.sensitive_apis || []),
      ...(context.rationale || []),
    ])
    const contextApis = dedupeStrings([
      ...(context.sensitive_apis || []),
      ...importedAndDynamicApis,
    ]).map(normalizeApiName)
    const matchingConstants = allConstants
      .filter((candidate) => constantMatchesFunction(candidate, context))
      .slice(0, maxConstantsPerFinding)
    const families = scoreFamilies(
      contextValues,
      contextApis,
      matchingConstants,
      Boolean(options.hasCryptoCapability),
      dynamicApis,
      'analysis.context.link',
      context.function,
      context.address
    )

    const ranked = [...families.entries()]
      .map(([family, payload]) => ({ family, ...payload }))
      .sort((left, right) => right.score - left.score)
      .slice(0, 2)

    for (const item of ranked) {
      const mode = detectMode(contextValues)
      const confidence = Number(
        clamp(
          0.32 +
            item.score +
            (matchingConstants.length > 0 ? 0.08 : 0) +
            (dynamicApis.some((api) => item.sourceApis.has(api)) ? 0.08 : 0),
          0.35,
          0.96
        ).toFixed(2)
      )
      findings.push({
        algorithm_family: item.family,
        algorithm_name: mode && !item.name.includes(mode) ? `${item.name}-${mode}` : item.name,
        mode,
        confidence,
        function: context.function || null,
        address: context.address || null,
        source_apis: [...item.sourceApis].slice(0, 6),
        evidence: item.evidence.slice(0, 8),
        candidate_constants: matchingConstants,
        dynamic_support: dynamicApis.some((api) => item.sourceApis.has(api)),
        xref_available: xrefAvailable,
      })
    }
  }

  if (findings.length === 0) {
    const sampleLevelFamilies = scoreFamilies(
      records.map((item) => item.value),
      importedAndDynamicApis,
      allConstants.slice(0, maxConstantsPerFinding),
      Boolean(options.hasCryptoCapability),
      dynamicApis,
      'crypto.identify'
    )

    for (const [family, payload] of [...sampleLevelFamilies.entries()].sort((left, right) => right[1].score - left[1].score)) {
      const mode = detectMode(records.map((item) => item.value))
      findings.push({
        algorithm_family: family,
        algorithm_name: mode && !payload.name.includes(mode) ? `${payload.name}-${mode}` : payload.name,
        mode,
        confidence: Number(clamp(0.28 + payload.score, 0.32, 0.9).toFixed(2)),
        function: null,
        address: null,
        source_apis: [...payload.sourceApis].slice(0, 6),
        evidence: payload.evidence.slice(0, 8),
        candidate_constants: allConstants.slice(0, maxConstantsPerFinding),
        dynamic_support: dynamicApis.some((api) => payload.sourceApis.has(api)),
        xref_available: xrefAvailable,
      })
    }
  }

  return {
    findings: findings
      .sort((left, right) => right.confidence - left.confidence)
      .slice(0, maxFindings),
    candidateConstants: allConstants,
    dynamicApis: importedAndDynamicApis.filter((api) => dynamicApis.includes(api)),
  }
}

function defaultCaptureTargets(family: CryptoFamily) {
  switch (family) {
    case 'aes':
    case 'rc4':
    case 'chacha20':
    case 'salsa20':
    case 'des':
      return ['rcx', 'rdx', 'r8', 'r9', 'return_value']
    case 'windows_cryptoapi':
    case 'cng':
    case 'rsa':
      return ['rcx', 'rdx', 'r8', 'r9']
    default:
      return ['rcx', 'rdx', 'return_value']
  }
}

export function buildBreakpointCandidates(options: {
  findings: CryptoFinding[]
  dynamicEvidence?: DynamicTraceSummary | null
  maxCandidates?: number
}) {
  const maxCandidates = options.maxCandidates ?? 12
  const dynamicApis = new Set((options.dynamicEvidence?.observed_apis || []).map(normalizeApiName))
  const candidates: BreakpointCandidate[] = []
  const seen = new Set<string>()

  for (const finding of options.findings) {
    if (finding.address || finding.function) {
      const key = `fn:${finding.address || finding.function}:${finding.algorithm_family}`
      if (!seen.has(key)) {
        seen.add(key)
        candidates.push({
          kind: 'function_entry',
          ...(finding.address ? { address: finding.address } : {}),
          ...(finding.function ? { function: finding.function } : {}),
          reason: `${finding.algorithm_name} candidate function entry`,
          confidence: finding.confidence,
          context_capture: defaultCaptureTargets(finding.algorithm_family),
          evidence_sources: dedupeStrings(finding.evidence.map((item) => `${item.source_tool}:${item.kind}`)),
          dynamic_support: finding.dynamic_support,
        })
      }
      if (finding.confidence >= 0.74) {
        const exitKey = `fn-exit:${finding.address || finding.function}:${finding.algorithm_family}`
        if (!seen.has(exitKey)) {
          seen.add(exitKey)
          candidates.push({
            kind: 'function_exit',
            ...(finding.address ? { address: finding.address } : {}),
            ...(finding.function ? { function: finding.function } : {}),
            reason: `${finding.algorithm_name} candidate function exit`,
            confidence: Number(clamp(finding.confidence - 0.06, 0.35, 0.92).toFixed(2)),
            context_capture: defaultCaptureTargets(finding.algorithm_family),
            evidence_sources: dedupeStrings(finding.evidence.map((item) => `${item.source_tool}:${item.kind}`)),
            dynamic_support: finding.dynamic_support,
          })
        }
      }
    }

    if (finding.source_apis.length > 0) {
      for (const api of finding.source_apis.slice(0, 2)) {
        const apiKey = `api:${api}`
        if (seen.has(apiKey)) {
          continue
        }
        seen.add(apiKey)
        candidates.push({
          kind: 'api_call',
          api,
          module: /^BCrypt/i.test(api) ? 'bcrypt.dll' : /^Crypt/i.test(api) ? 'advapi32.dll' : undefined,
          reason: `${api} is a likely crypto transition point`,
          confidence: Number(clamp(finding.confidence - 0.08 + (dynamicApis.has(api) ? 0.08 : 0), 0.35, 0.94).toFixed(2)),
          context_capture: defaultCaptureTargets(finding.algorithm_family),
          evidence_sources: dedupeStrings([
            ...finding.evidence.map((item) => `${item.source_tool}:${item.kind}`),
            ...(dynamicApis.has(api) ? ['dynamic.trace:observed_api'] : []),
          ]),
          dynamic_support: dynamicApis.has(api),
        })
      }
    }
  }

  return candidates
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, maxCandidates)
}

export function summarizeCryptoFindings(findings: CryptoFinding[]) {
  if (findings.length === 0) {
    return 'No strong cryptographic function evidence was localized.'
  }
  const families = dedupeStrings(findings.map((item) => item.algorithm_name))
  const localized = findings.filter((item) => item.address || item.function).length
  return `Recovered ${findings.length} crypto candidate finding(s) across ${families.join(', ')} with ${localized} function-localized result(s).`
}

export function summarizeBreakpointCandidates(candidates: BreakpointCandidate[]) {
  if (candidates.length === 0) {
    return 'No strong breakpoint candidates were ranked from the available crypto or API evidence.'
  }
  const top = candidates[0]
  const label = top.function || top.address || top.api || 'target'
  return `Ranked ${candidates.length} breakpoint candidate(s); top candidate is ${label} at confidence ${top.confidence.toFixed(2)}.`
}

export function summarizeConditionGroup(condition: TraceConditionGroup) {
  if (condition.predicates.length === 0) {
    return 'no additional predicate filters'
  }
  return `${condition.logic}(${condition.predicates
    .map((predicate) => {
      const target =
        predicate.source === 'register'
          ? predicate.register
          : predicate.argument_index !== undefined
            ? `${predicate.source}[${predicate.argument_index}]`
            : predicate.source
      return `${target} ${predicate.operator} ${String(predicate.value)}`
    })
    .join(', ')})`
}

export function summarizeCapturePlan(capture: TraceCapturePlan) {
  const parts: string[] = []
  if (capture.registers.length > 0) {
    parts.push(`registers=${capture.registers.join(',')}`)
  }
  if (capture.arguments.length > 0) {
    parts.push(`args=${capture.arguments.join(',')}`)
  }
  if (capture.include_return_value) {
    parts.push('return_value')
  }
  if (capture.stack_bytes > 0) {
    parts.push(`stack=${capture.stack_bytes}B`)
  }
  if (capture.memory_slices.length > 0) {
    parts.push(`memory_slices=${capture.memory_slices.length}`)
  }
  return parts.join(', ') || 'default context capture'
}

function buildDefaultTraceCapturePlan(candidate: BreakpointCandidate): TraceCapturePlan {
  const registers = candidate.context_capture
    .filter((item) => item !== 'return_value' && /^r[a-z0-9]+$/i.test(item))
    .slice(0, 8)
  return {
    registers,
    arguments: [],
    include_return_value: candidate.context_capture.includes('return_value'),
    stack_bytes: candidate.kind === 'api_call' ? 96 : 64,
    memory_slices:
      candidate.kind === 'api_call'
        ? [
            {
              source: 'argument',
              argument_index: 0,
              max_bytes: 96,
              label: 'primary_buffer',
            },
          ]
        : [],
  }
}

export function buildNormalizedTracePlan(options: {
  breakpoint: BreakpointCandidate
  condition?: Partial<TraceConditionGroup> | null
  capture?: Partial<TraceCapturePlan> | null
  limits?: Partial<NormalizedTracePlan['limits']> | null
  runtimeReady: boolean
}) : NormalizedTracePlan {
  const breakpoint = options.breakpoint
  const defaultCapture = buildDefaultTraceCapturePlan(breakpoint)
  const rawCapture = options.capture || {}
  const registers = dedupeStrings(
    Array.isArray(rawCapture.registers)
      ? rawCapture.registers.map((item) => String(item))
      : defaultCapture.registers
  ).slice(0, 8)
  const argumentsList = Array.from(
    new Set(
      Array.isArray(rawCapture.arguments)
        ? rawCapture.arguments.map((item) => Number(item)).filter((item) => Number.isInteger(item) && item >= 0 && item <= 15)
        : defaultCapture.arguments
    )
  ).slice(0, 8)
  const includeReturnValue =
    typeof rawCapture.include_return_value === 'boolean'
      ? rawCapture.include_return_value
      : defaultCapture.include_return_value
  const stackBytes = clamp(
    typeof rawCapture.stack_bytes === 'number' ? Math.trunc(rawCapture.stack_bytes) : defaultCapture.stack_bytes,
    0,
    512
  )
  const memorySlices = (Array.isArray(rawCapture.memory_slices) ? rawCapture.memory_slices : defaultCapture.memory_slices)
    .map((item) => {
      const source = item?.source === 'register' ? ('register' as const) : ('argument' as const)
      const maxBytes = clamp(Number(item?.max_bytes || 64), 1, 512)
      return {
        source,
        ...(source === 'register' && typeof item?.register === 'string' ? { register: item.register } : {}),
        ...(source === 'argument' ? { argument_index: clamp(Number(item?.argument_index || 0), 0, 15) } : {}),
        max_bytes: maxBytes,
        ...(typeof item?.label === 'string' && item.label.trim().length > 0 ? { label: item.label.trim() } : {}),
      }
    })
    .slice(0, 4)

  const condition = TraceConditionGroupSchema.parse({
    logic: options.condition?.logic || 'all',
    predicates: Array.isArray(options.condition?.predicates) ? options.condition?.predicates : [],
  })

  const scriptName =
    breakpoint.api && /^(bcrypt|crypt|aes_)/i.test(breakpoint.api)
      ? 'crypto_finder'
      : breakpoint.reason.toLowerCase().includes('crypto')
        ? 'crypto_finder'
        : 'api_trace'
  const recommendedTool = breakpoint.kind === 'api_call' ? 'frida.runtime.instrument' : 'frida.script.inject'

  return {
    breakpoint,
    condition,
    capture: {
      registers,
      arguments: argumentsList,
      include_return_value: includeReturnValue,
      stack_bytes: stackBytes,
      memory_slices: memorySlices,
    },
    limits: {
      max_hits: clamp(Number(options.limits?.max_hits || 12), 1, 100),
      max_events: clamp(Number(options.limits?.max_events || 64), 1, 500),
      max_memory_bytes: clamp(Number(options.limits?.max_memory_bytes || 256), 0, 2048),
    },
    runtime_mapping: {
      recommended_tool: recommendedTool,
      suggested_script_name: scriptName,
      ready: options.runtimeReady,
      rationale:
        recommendedTool === 'frida.runtime.instrument'
          ? 'API-oriented breakpoint candidates map naturally to frida.runtime.instrument with a built-in tracing script.'
          : 'Function-entry and exit candidates need a focused Frida hook script, so frida.script.inject is the recommended next tool.',
    },
  }
}

export function summarizeNormalizedTracePlan(plan: NormalizedTracePlan) {
  const target = plan.breakpoint.function || plan.breakpoint.address || plan.breakpoint.api || 'target'
  return `Prepared a bounded trace plan for ${target} using ${summarizeConditionGroup(plan.condition)} with ${summarizeCapturePlan(plan.capture)}.`
}
