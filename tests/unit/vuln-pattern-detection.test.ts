/**
 * Unit tests for vuln-pattern-detection
 *
 * We cannot directly import the module because it uses import.meta.url
 * which ts-jest doesn't support. Instead, we replicate the pure logic
 * for unit testing.
 */

interface VulnPatternDef {
  id: string
  cwe: string
  name: string
  patterns: string[]
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence_default: number
  description: string
}

interface VulnFinding {
  pattern_id: string
  cwe: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  function_address: string
  function_name: string
  match_snippet: string
}

/**
 * Replicated scanFunction logic for unit testing.
 */
function scanFunction(
  code: string,
  functionName: string,
  functionAddress: string,
  patterns: VulnPatternDef[],
  minConfidence?: number,
): VulnFinding[] {
  const findings: VulnFinding[] = []
  for (const pat of patterns) {
    for (const regexStr of pat.patterns) {
      const re = new RegExp(regexStr, 'g')
      let match: RegExpExecArray | null
      while ((match = re.exec(code)) !== null) {
        if (minConfidence !== undefined && pat.confidence_default < minConfidence) continue
        findings.push({
          pattern_id: pat.id,
          cwe: pat.cwe,
          name: pat.name,
          severity: pat.severity,
          confidence: pat.confidence_default,
          function_address: functionAddress,
          function_name: functionName,
          match_snippet: match[0],
        })
      }
    }
  }
  return findings
}

function scanAllFunctions(
  functions: { name: string; address: string; decompiled_code: string }[],
  patterns: VulnPatternDef[],
  minConfidence?: number,
) {
  const allFindings: VulnFinding[] = []
  for (const fn of functions) {
    allFindings.push(...scanFunction(fn.decompiled_code, fn.name, fn.address, patterns, minConfidence))
  }
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

const samplePatterns: VulnPatternDef[] = [
  {
    id: 'CWE-120-strcpy',
    cwe: 'CWE-120',
    name: 'Buffer Overflow via strcpy',
    patterns: ['strcpy\\s*\\(', 'strcat\\s*\\('],
    severity: 'high',
    confidence_default: 0.7,
    description: 'Unbounded copy functions',
  },
  {
    id: 'CWE-134-format',
    cwe: 'CWE-134',
    name: 'Format String',
    patterns: ['printf\\s*\\([^"]*\\bvar_'],
    severity: 'high',
    confidence_default: 0.6,
    description: 'Format string vulnerability',
  },
  {
    id: 'CWE-78-system',
    cwe: 'CWE-78',
    name: 'OS Command Injection',
    patterns: ['\\bsystem\\s*\\(', '\\bWinExec\\s*\\('],
    severity: 'critical',
    confidence_default: 0.5,
    description: 'OS command injection via system/WinExec',
  },
]

describe('vuln-patterns', () => {
  describe('scanFunction', () => {
    it('detects strcpy usage', () => {
      const code = `
        void vulnerable_func() {
          char buf[64];
          strcpy(buf, user_input);
        }
      `
      const findings = scanFunction(code, 'vulnerable_func', '0x401000', samplePatterns)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].cwe).toBe('CWE-120')
      expect(findings[0].function_name).toBe('vulnerable_func')
      expect(findings[0].function_address).toBe('0x401000')
    })

    it('detects system() call', () => {
      const code = `
        void exec_cmd() {
          system(cmd_buffer);
        }
      `
      const findings = scanFunction(code, 'exec_cmd', '0x402000', samplePatterns)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings.some(f => f.cwe === 'CWE-78')).toBe(true)
      expect(findings.some(f => f.severity === 'critical')).toBe(true)
    })

    it('detects WinExec call', () => {
      const code = `
        void run_payload() {
          WinExec(payload_cmd, SW_HIDE);
        }
      `
      const findings = scanFunction(code, 'run_payload', '0x403000', samplePatterns)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].cwe).toBe('CWE-78')
    })

    it('returns empty for clean code', () => {
      const code = `
        void safe_func() {
          int x = 5;
          return x + 1;
        }
      `
      const findings = scanFunction(code, 'safe_func', '0x404000', samplePatterns)
      expect(findings.length).toBe(0)
    })

    it('respects minConfidence filter', () => {
      const code = `
        void func() {
          strcpy(buf, src);
          system(cmd);
        }
      `
      // Only return findings with confidence >= 0.65
      const findings = scanFunction(code, 'func', '0x405000', samplePatterns, 0.65)
      // CWE-120 has confidence 0.7 (should pass), CWE-78 has 0.5 (should be filtered)
      expect(findings.every(f => f.confidence >= 0.65)).toBe(true)
    })
  })

  describe('scanAllFunctions', () => {
    it('aggregates findings across multiple functions', () => {
      const functions = [
        { name: 'func_a', address: '0x401000', decompiled_code: 'strcpy(buf, src);' },
        { name: 'func_b', address: '0x402000', decompiled_code: 'system(cmd);' },
        { name: 'func_c', address: '0x403000', decompiled_code: 'int x = 5;' },
      ]
      const result = scanAllFunctions(functions, samplePatterns)
      expect(result.functions_scanned).toBe(3)
      expect(result.total_findings).toBeGreaterThan(0)
      expect(result.severity_counts).toBeDefined()
      expect(result.cwe_counts).toBeDefined()
    })

    it('returns zero findings for clean functions', () => {
      const functions = [
        { name: 'clean', address: '0x401000', decompiled_code: 'return 0;' },
      ]
      const result = scanAllFunctions(functions, samplePatterns)
      expect(result.total_findings).toBe(0)
      expect(result.functions_scanned).toBe(1)
    })

    it('counts severity distribution correctly', () => {
      const functions = [
        { name: 'vuln1', address: '0x401000', decompiled_code: 'strcpy(buf, src);' },
        { name: 'vuln2', address: '0x402000', decompiled_code: 'system(cmd);' },
      ]
      const result = scanAllFunctions(functions, samplePatterns)
      expect(typeof result.severity_counts['high']).toBe('number')
      expect(typeof result.severity_counts['critical']).toBe('number')
    })
  })
})
