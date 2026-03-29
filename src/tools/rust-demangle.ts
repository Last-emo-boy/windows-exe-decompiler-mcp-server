/**
 * Rust symbol demangling and normalization utilities
 * Tasks: rust-demangle-and-symbol-recovery 1.1, 1.2
 */

// Rust v0 mangling pattern: _RNvCsXXXXXXX_7crate_name
// Rust legacy pattern: _ZN$hash$crate_name$hash$func_nameE
const RUST_V0_PREFIX = '_RNv'
const RUST_LEGACY_PREFIX = '_ZN'

export interface DemangledSymbol {
  raw: string
  demangled: string
  normalized: string
  isRust: boolean
  confidence: number
  preview?: string
  components?: {
    crate?: string
    module?: string
    function?: string
    generics?: string
  }
}

/**
 * Attempt to demangle a Rust symbol
 */
export function demangleRustSymbol(mangled: string): DemangledSymbol | null {
  if (!mangled.startsWith(RUST_V0_PREFIX) && !mangled.startsWith(RUST_LEGACY_PREFIX)) {
    return null
  }

  try {
    const components = parseRustSymbol(mangled)
    if (!components) {
      return null
    }

    const demangled = buildDemangledName(components)
    const normalized = normalizeRustName(demangled)
    const preview = boundedPreview(normalized, 64)

    return {
      raw: mangled,
      demangled,
      normalized,
      isRust: true,
      confidence: computeDemangleConfidence(components),
      preview,
      components,
    }
  } catch {
    return null
  }
}

/**
 * Normalize a demangled Rust name for analyst consumption
 */
export function normalizeRustName(name: string): string {
  return name
    // Remove hash suffixes like hXXXXXXX
    .replace(/h[0-9a-f]{7,}$/i, '')
    // Remove generic instantiations for cleaner names
    .replace(/<.*>/g, '')
    // Normalize closure markers
    .replace(/\{closure#\d+\}/g, '{closure}')
    // Normalize async markers
    .replace(/\{async_closure#\d+\}/g, '{async_closure}')
    // Clean up multiple underscores
    .replace(/_{2,}/g, '_')
    .trim()
}

/**
 * Create a bounded preview of a long symbol
 */
export function boundedPreview(name: string, maxLength: number = 64): string {
  if (name.length <= maxLength) {
    return name
  }

  // Try to cut at a word boundary
  const cutPoint = name.lastIndexOf('_', maxLength - 3)
  if (cutPoint > maxLength / 2) {
    return name.substring(0, cutPoint) + '...'
  }

  return name.substring(0, maxLength - 3) + '...'
}

/**
 * Parse Rust symbol into components
 */
function parseRustSymbol(mangled: string): DemangledSymbol['components'] | null {
  // V0 mangling: _RNvCsXXXXXXX_7crate_name::module::function
  if (mangled.startsWith(RUST_V0_PREFIX)) {
    return parseRustV0Symbol(mangled)
  }

  // Legacy mangling: _ZN$hash$crate_name$hash$func_nameE
  if (mangled.startsWith(RUST_LEGACY_PREFIX)) {
    return parseRustLegacySymbol(mangled)
  }

  return null
}

/**
 * Parse Rust v0 mangled symbol
 */
function parseRustV0Symbol(mangled: string): DemangledSymbol['components'] | null {
  // Simple heuristic parsing - real implementation would use full v0 spec
  const parts = mangled.split('_').filter(p => p.length > 0)
  
  if (parts.length < 2) {
    return null
  }

  // Try to extract crate name from encoded parts
  const crateMatch = parts.find(p => /^[0-9a-zA-Z]+$/.test(p) && p.length > 4)
  
  // Look for path-like segments
  const pathSegments = parts.filter(p => /^[a-z][a-z0-9_]*$/i.test(p) && p.length > 1)
  
  return {
    crate: crateMatch || pathSegments[0],
    module: pathSegments.length > 2 ? pathSegments[pathSegments.length - 2] : undefined,
    function: pathSegments[pathSegments.length - 1],
  }
}

/**
 * Parse Rust legacy mangled symbol
 */
function parseRustLegacySymbol(mangled: string): DemangledSymbol['components'] | null {
  // Remove prefix and suffix
  const inner = mangled.substring(2, mangled.length - 1) // Remove _ZN and E
  
  // Split by hash separators
  const parts = inner.split(/\$hash\$|\$/)
  
  if (parts.length < 2) {
    return null
  }

  return {
    crate: parts[0],
    function: parts[parts.length - 1],
  }
}

/**
 * Build demangled name from components
 */
function buildDemangledName(components: DemangledSymbol['components']): string {
  const parts: string[] = []
  
  if (components.crate) {
    parts.push(components.crate)
  }
  if (components.module) {
    parts.push(components.module)
  }
  if (components.function) {
    parts.push(components.function)
  }

  return parts.join('::')
}

/**
 * Compute confidence score for demangled symbol
 */
function computeDemangleConfidence(components: DemangledSymbol['components']): number {
  let score = 0.5 // Base confidence for successful parse

  if (components.crate) {
    score += 0.2
  }
  if (components.function) {
    score += 0.2
  }
  if (components.module) {
    score += 0.1
  }

  return Math.min(score, 1.0)
}

/**
 * Normalize a list of symbols, preserving raw and normalized forms
 */
export function normalizeSymbolList(symbols: string[]): DemangledSymbol[] {
  const results: DemangledSymbol[] = []

  for (const symbol of symbols) {
    const demangled = demangleRustSymbol(symbol)
    if (demangled) {
      results.push(demangled)
    } else {
      // Keep non-Rust symbols as-is
      results.push({
        raw: symbol,
        demangled: symbol,
        normalized: symbol,
        isRust: false,
        confidence: 1.0,
      })
    }
  }

  return results
}

/**
 * Merge demangled symbols with existing recovered names
 */
export function mergeWithRecoveredNames(
  demangled: DemangledSymbol[],
  existingNames: Array<{ address: string; name: string; source?: string }>
): Array<{
  address: string
  name: string
  source: string
  confidence: number
  isDemangled: boolean
}> {
  const merged = new Map<string, {
    address: string
    name: string
    source: string
    confidence: number
    isDemangled: boolean
  }>()

  // Add existing names first
  for (const item of existingNames) {
    const key = item.address
    merged.set(key, {
      address: item.address,
      name: item.name,
      source: item.source || 'recovered',
      confidence: 0.7,
      isDemangled: false,
    })
  }

  // Override with demangled names where available
  for (const sym of demangled) {
    // Find matching address by raw symbol (simplified - real impl would use address map)
    const existing = Array.from(merged.values()).find(e => e.name === sym.raw)
    if (existing) {
      existing.name = sym.normalized
      existing.source = 'demangled'
      existing.confidence = sym.confidence
      existing.isDemangled = true
    }
  }

  return Array.from(merged.values())
}
