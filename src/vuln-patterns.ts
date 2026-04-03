/**
 * Vulnerability pattern matching engine — scans decompiled code for CWE patterns.
 */

import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'

// ============================================================================
// Types
// ============================================================================

export interface VulnPatternDef {
  id: string
  cwe: string
  name: string
  patterns: string[]
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence_default: number
  description: string
}

export interface VulnPatternDB {
  version: string
  patterns: VulnPatternDef[]
}

export interface VulnFinding {
  pattern_id: string
  cwe: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  function_address: string
  function_name: string
  match_snippet: string
  line_number?: number
}

export interface VulnScanResult {
  findings: VulnFinding[]
  functions_scanned: number
  total_findings: number
  severity_counts: Record<string, number>
  cwe_counts: Record<string, number>
}

// ============================================================================
// Pattern loading
// ============================================================================

let cachedPatterns: VulnPatternDB | null = null

export async function loadPatterns(configPath?: string): Promise<VulnPatternDB> {
  if (cachedPatterns) return cachedPatterns

  const defaultPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'data',
    'vuln-patterns.json'
  )

  const filePath = configPath ?? defaultPath
  const content = await fs.readFile(filePath, 'utf8')
  cachedPatterns = JSON.parse(content) as VulnPatternDB
  return cachedPatterns
}

export function loadPatternsSync(patterns: VulnPatternDef[]): VulnPatternDB {
  const db: VulnPatternDB = { version: '1.0.0', patterns }
  cachedPatterns = db
  return db
}

// ============================================================================
// Pattern scanning
// ============================================================================

export function scanFunction(
  code: string,
  functionName: string,
  functionAddress: string,
  patterns: VulnPatternDef[],
  minConfidence: number = 0
): VulnFinding[] {
  const findings: VulnFinding[] = []

  for (const pattern of patterns) {
    if (pattern.confidence_default < minConfidence) continue

    for (const regexStr of pattern.patterns) {
      let regex: RegExp
      try {
        regex = new RegExp(regexStr, 'gm')
      } catch {
        continue
      }

      let match: RegExpExecArray | null
      while ((match = regex.exec(code)) !== null) {
        // Extract snippet around match
        const start = Math.max(0, match.index - 40)
        const end = Math.min(code.length, match.index + match[0].length + 40)
        const snippet = code.slice(start, end).replace(/\n/g, ' ').trim()

        // Estimate line number
        const lineNumber = code.slice(0, match.index).split('\n').length

        // Adjust confidence based on context
        let confidence = pattern.confidence_default

        // Boost if inside a function that takes user input indicators
        if (
          /\b(recv|read|fgets|fread|getenv|argv|scanf|ReadFile|InternetReadFile)\b/.test(code)
        ) {
          confidence = Math.min(1.0, confidence + 0.15)
        }

        // Reduce if safe variant is also present nearby
        const safeVariants: Record<string, string[]> = {
          strcpy: ['strncpy', 'strcpy_s', 'StringCchCopy'],
          strcat: ['strncat', 'strcat_s', 'StringCchCat'],
          sprintf: ['snprintf', 'sprintf_s', 'StringCchPrintf'],
          gets: ['fgets', 'gets_s'],
        }
        for (const [unsafe, safeList] of Object.entries(safeVariants)) {
          if (match[0].includes(unsafe)) {
            for (const safe of safeList) {
              if (code.includes(safe)) {
                confidence = Math.max(0, confidence - 0.2)
              }
            }
          }
        }

        if (confidence >= minConfidence) {
          findings.push({
            pattern_id: pattern.id,
            cwe: pattern.cwe,
            name: pattern.name,
            severity: pattern.severity,
            confidence,
            function_address: functionAddress,
            function_name: functionName,
            match_snippet: snippet.slice(0, 200),
            line_number: lineNumber,
          })
        }

        // Only report first match per pattern per function
        break
      }
    }
  }

  return findings
}

// ============================================================================
// Full scan of decompiled functions
// ============================================================================

export function scanAllFunctions(
  functions: Array<{
    name: string
    address: string
    decompiled_code: string
  }>,
  patterns: VulnPatternDef[],
  minConfidence: number = 0
): VulnScanResult {
  const allFindings: VulnFinding[] = []

  for (const fn of functions) {
    if (!fn.decompiled_code) continue
    const findings = scanFunction(
      fn.decompiled_code,
      fn.name,
      fn.address,
      patterns,
      minConfidence
    )
    allFindings.push(...findings)
  }

  // Compute severity counts
  const severity_counts: Record<string, number> = {}
  const cwe_counts: Record<string, number> = {}
  for (const f of allFindings) {
    severity_counts[f.severity] = (severity_counts[f.severity] ?? 0) + 1
    cwe_counts[f.cwe] = (cwe_counts[f.cwe] ?? 0) + 1
  }

  return {
    findings: allFindings,
    functions_scanned: functions.length,
    total_findings: allFindings.length,
    severity_counts,
    cwe_counts,
  }
}
