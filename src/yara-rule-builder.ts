/**
 * YARA rule builder — constructs YARA rules from analysis evidence.
 */

import { createHash } from 'crypto'

// ============================================================================
// Types
// ============================================================================

export type Strictness = 'tight' | 'balanced' | 'loose'

export interface RuleMeta {
  sample_id: string
  description?: string
  author?: string
  date?: string
  hash?: string
  family?: string
}

export interface RuleEvidence {
  unique_strings: string[]
  suspicious_imports: string[]
  all_imports: string[]
  byte_patterns: Array<{ offset: number; hex: string; description?: string }>
  pe_imphash?: string
  file_size?: number
  sections?: Array<{ name: string; entropy: number }>
}

export interface ScoredRule {
  rule_text: string
  rule_name: string
  score: number
  score_breakdown: {
    string_uniqueness: number
    import_specificity: number
    byte_pattern_quality: number
    condition_strictness: number
  }
}

// ============================================================================
// Common Windows strings to penalize
// ============================================================================

const COMMON_STRINGS = new Set([
  'kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll', 'msvcrt.dll',
  'GetProcAddress', 'LoadLibraryA', 'GetModuleHandleA', 'VirtualAlloc',
  'VirtualFree', 'ExitProcess', 'CloseHandle', 'CreateFileA', 'ReadFile',
  'WriteFile', 'GetLastError', 'SetLastError', 'GetCurrentProcess',
  'HeapAlloc', 'HeapFree', 'GetCommandLineA', 'GetStartupInfoA',
  'This program cannot be run in DOS mode', '.text', '.data', '.rdata',
  '.rsrc', '.reloc', 'KERNEL32.dll', 'USER32.dll',
])

// ============================================================================
// Rule construction helpers
// ============================================================================

function sanitizeRuleName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&')
}

function escapeYaraString(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
}

function buildMetaBlock(meta: RuleMeta): string {
  const lines = ['    meta:']
  if (meta.description) lines.push(`        description = "${escapeYaraString(meta.description)}"`)
  lines.push(`        author = "${escapeYaraString(meta.author ?? 'auto-generated')}"`)
  lines.push(`        date = "${meta.date ?? new Date().toISOString().slice(0, 10)}"`)
  if (meta.hash) lines.push(`        hash = "${meta.hash}"`)
  if (meta.family) lines.push(`        family = "${escapeYaraString(meta.family)}"`)
  lines.push(`        sample_id = "${escapeYaraString(meta.sample_id)}"`)
  return lines.join('\n')
}

// ============================================================================
// Rule builders
// ============================================================================

export function buildStringRule(strings: string[], meta: RuleMeta): string {
  const filtered = strings.filter(
    (s) => s.length >= 6 && s.length <= 200 && !COMMON_STRINGS.has(s)
  )
  if (filtered.length === 0) return ''

  const selected = filtered.slice(0, 30)
  const ruleName = sanitizeRuleName(`string_${meta.sample_id.slice(7, 19)}`)

  const stringDefs = selected
    .map((s, i) => `        $s${i} = "${escapeYaraString(s)}"`)
    .join('\n')

  const minMatch = Math.max(1, Math.floor(selected.length * 0.6))

  return [
    `rule ${ruleName}`,
    '{',
    buildMetaBlock(meta),
    '    strings:',
    stringDefs,
    '    condition:',
    `        ${minMatch} of ($s*)`,
    '}',
  ].join('\n')
}

export function buildImportRule(imports: string[], meta: RuleMeta): string {
  const suspicious = imports.filter(
    (imp) => !COMMON_STRINGS.has(imp) && imp.length >= 4
  )
  if (suspicious.length === 0) return ''

  const selected = suspicious.slice(0, 20)
  const ruleName = sanitizeRuleName(`imports_${meta.sample_id.slice(7, 19)}`)

  const importDefs = selected
    .map((imp, i) => `        $imp${i} = "${escapeYaraString(imp)}"`)
    .join('\n')

  const minMatch = Math.max(1, Math.floor(selected.length * 0.7))

  return [
    `rule ${ruleName}`,
    '{',
    buildMetaBlock(meta),
    '    strings:',
    importDefs,
    '    condition:',
    `        uint16(0) == 0x5A4D and ${minMatch} of ($imp*)`,
    '}',
  ].join('\n')
}

export function buildBytePatternRule(
  patterns: Array<{ offset: number; hex: string; description?: string }>,
  meta: RuleMeta
): string {
  if (patterns.length === 0) return ''

  const selected = patterns.slice(0, 10)
  const ruleName = sanitizeRuleName(`bytes_${meta.sample_id.slice(7, 19)}`)

  const hexDefs = selected
    .map((p, i) => `        $hex${i} = { ${p.hex} }`)
    .join('\n')

  return [
    `rule ${ruleName}`,
    '{',
    buildMetaBlock(meta),
    '    strings:',
    hexDefs,
    '    condition:',
    `        uint16(0) == 0x5A4D and any of ($hex*)`,
    '}',
  ].join('\n')
}

export function buildHybridRule(
  evidence: RuleEvidence,
  strictness: Strictness,
  meta: RuleMeta
): string {
  const ruleName = sanitizeRuleName(`hybrid_${meta.sample_id.slice(7, 19)}`)
  const stringDefs: string[] = []
  const conditions: string[] = ['uint16(0) == 0x5A4D']
  let idx = 0

  // Strings
  const uniqueStrings = evidence.unique_strings
    .filter((s) => s.length >= 6 && !COMMON_STRINGS.has(s))
    .slice(0, strictness === 'tight' ? 20 : strictness === 'balanced' ? 12 : 6)

  for (const s of uniqueStrings) {
    stringDefs.push(`        $s${idx} = "${escapeYaraString(s)}"`)
    idx++
  }

  // Suspicious imports
  const susImports = evidence.suspicious_imports
    .filter((s) => !COMMON_STRINGS.has(s))
    .slice(0, strictness === 'tight' ? 10 : 5)

  for (const imp of susImports) {
    stringDefs.push(`        $imp${idx} = "${escapeYaraString(imp)}"`)
    idx++
  }

  // Byte patterns
  const bytePatterns = evidence.byte_patterns.slice(
    0,
    strictness === 'tight' ? 5 : 2
  )
  for (const bp of bytePatterns) {
    stringDefs.push(`        $hex${idx} = { ${bp.hex} }`)
    idx++
  }

  if (stringDefs.length === 0) return ''

  // Build condition based on strictness
  const totalPatterns = uniqueStrings.length + susImports.length + bytePatterns.length
  let minMatch: number
  switch (strictness) {
    case 'tight':
      minMatch = Math.max(1, Math.floor(totalPatterns * 0.8))
      break
    case 'balanced':
      minMatch = Math.max(1, Math.floor(totalPatterns * 0.6))
      break
    case 'loose':
      minMatch = Math.max(1, Math.floor(totalPatterns * 0.3))
      break
  }

  conditions.push(`${minMatch} of them`)

  if (evidence.file_size && strictness === 'tight') {
    const lower = Math.floor(evidence.file_size * 0.5)
    const upper = Math.ceil(evidence.file_size * 2.0)
    conditions.push(`filesize > ${lower} and filesize < ${upper}`)
  }

  if (evidence.pe_imphash && strictness === 'tight') {
    stringDefs.push(`        $imphash = "${escapeYaraString(evidence.pe_imphash)}"`)
  }

  return [
    `rule ${ruleName}`,
    '{',
    buildMetaBlock({ ...meta, description: `Hybrid ${strictness} rule` }),
    '    strings:',
    stringDefs.join('\n'),
    '    condition:',
    `        ${conditions.join(' and ')}`,
    '}',
  ].join('\n')
}

// ============================================================================
// Evidence extraction
// ============================================================================

export function extractRuleEvidence(artifactData: Record<string, unknown>): RuleEvidence {
  const evidence: RuleEvidence = {
    unique_strings: [],
    suspicious_imports: [],
    all_imports: [],
    byte_patterns: [],
  }

  // Extract strings
  const stringsData = artifactData.strings as unknown[] | undefined
  if (Array.isArray(stringsData)) {
    evidence.unique_strings = stringsData
      .map((s) =>
        typeof s === 'string' ? s : s && typeof s === 'object' ? String((s as Record<string, unknown>).value ?? '') : ''
      )
      .filter((s) => s.length >= 6 && !COMMON_STRINGS.has(s))
      .slice(0, 100)
  }

  // Extract imports
  const importsData = artifactData.imports as unknown[] | undefined
  if (Array.isArray(importsData)) {
    for (const imp of importsData) {
      if (typeof imp === 'string') {
        evidence.all_imports.push(imp)
      } else if (imp && typeof imp === 'object') {
        const obj = imp as Record<string, unknown>
        if (typeof obj.name === 'string') evidence.all_imports.push(obj.name)
        if (Array.isArray(obj.functions)) {
          for (const fn of obj.functions) {
            if (typeof fn === 'string') evidence.all_imports.push(fn)
            else if (fn && typeof fn === 'object' && typeof (fn as Record<string, unknown>).name === 'string') {
              evidence.all_imports.push((fn as Record<string, unknown>).name as string)
            }
          }
        }
      }
    }
  }

  // Mark suspicious imports
  const SUSPICIOUS_APIS = [
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection',
    'RtlCreateUserThread', 'QueueUserAPC', 'SetWindowsHookEx', 'CreateToolhelp32Snapshot',
    'Process32First', 'Process32Next', 'OpenProcess', 'NtCreateThreadEx',
    'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'URLDownloadToFileA',
    'InternetOpenA', 'InternetConnectA', 'HttpOpenRequestA', 'HttpSendRequestA',
    'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt',
    'RegSetValueExA', 'RegCreateKeyExA', 'NtSetInformationProcess',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  ]
  const suspSet = new Set(SUSPICIOUS_APIS.map((s) => s.toLowerCase()))
  evidence.suspicious_imports = evidence.all_imports.filter((imp) =>
    suspSet.has(imp.toLowerCase())
  )

  // PE imphash
  if (typeof artifactData.pe_imphash === 'string') {
    evidence.pe_imphash = artifactData.pe_imphash
  }

  // File size
  if (typeof artifactData.file_size === 'number') {
    evidence.file_size = artifactData.file_size
  }

  return evidence
}

// ============================================================================
// Quality scoring
// ============================================================================

export function scoreRule(
  ruleText: string,
  evidence: RuleEvidence
): { score: number; breakdown: ScoredRule['score_breakdown'] } {
  if (!ruleText) return { score: 0, breakdown: { string_uniqueness: 0, import_specificity: 0, byte_pattern_quality: 0, condition_strictness: 0 } }

  // String uniqueness: penalize common strings
  const stringMatches = ruleText.match(/\$s\d+/g) ?? []
  const uniqueCount = evidence.unique_strings.filter(
    (s) => !COMMON_STRINGS.has(s) && s.length >= 8
  ).length
  const string_uniqueness = Math.min(30, (uniqueCount / Math.max(1, stringMatches.length)) * 30)

  // Import specificity
  const importMatches = ruleText.match(/\$imp\d+/g) ?? []
  const susCount = evidence.suspicious_imports.length
  const import_specificity = Math.min(25, (susCount / Math.max(1, importMatches.length + 1)) * 25)

  // Byte pattern quality
  const hexMatches = ruleText.match(/\$hex\d+/g) ?? []
  const byte_pattern_quality = Math.min(20, hexMatches.length * 5)

  // Condition strictness (more conditions = stricter)
  const conditionLines = ruleText.match(/condition:[\s\S]*?}/)?.[0] ?? ''
  const andCount = (conditionLines.match(/\band\b/g) ?? []).length
  const condition_strictness = Math.min(25, (andCount + 1) * 6)

  const score = Math.round(string_uniqueness + import_specificity + byte_pattern_quality + condition_strictness)

  return {
    score: Math.min(100, score),
    breakdown: {
      string_uniqueness: Math.round(string_uniqueness),
      import_specificity: Math.round(import_specificity),
      byte_pattern_quality: Math.round(byte_pattern_quality),
      condition_strictness: Math.round(condition_strictness),
    },
  }
}
