/**
 * KB capa rule importer — parses capa YAML rules into KB entries.
 */

import fs from 'fs/promises'
import path from 'path'
import { parse as parseYaml } from 'yaml'

export interface CapaKbEntry {
  rule_name: string
  description: string
  apis: string[]
  strings: string[]
  attack_techniques: string[]
  category: string
}

export async function parseCapaRules(dirPath: string): Promise<CapaKbEntry[]> {
  const entries: CapaKbEntry[] = []

  let files: string[]
  try {
    files = await collectYamlFiles(dirPath)
  } catch {
    return entries
  }

  for (const filePath of files) {
    try {
      const content = await fs.readFile(filePath, 'utf8')
      const doc = parseYaml(content)
      if (!doc || typeof doc !== 'object') continue

      const entry = extractCapaEntry(doc as Record<string, unknown>)
      if (entry) entries.push(entry)
    } catch {
      // Skip unparseable files
    }
  }

  return entries
}

async function collectYamlFiles(dirPath: string, maxDepth = 3): Promise<string[]> {
  const files: string[] = []
  if (maxDepth <= 0) return files

  const entries = await fs.readdir(dirPath, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name)
    if (entry.isDirectory()) {
      const subFiles = await collectYamlFiles(fullPath, maxDepth - 1)
      files.push(...subFiles)
    } else if (entry.name.endsWith('.yml') || entry.name.endsWith('.yaml')) {
      files.push(fullPath)
    }
  }
  return files
}

function extractCapaEntry(doc: Record<string, unknown>): CapaKbEntry | null {
  const rule = doc.rule as Record<string, unknown> | undefined
  if (!rule) return null

  const meta = rule.meta as Record<string, unknown> | undefined
  const features = rule.features as unknown[] | undefined

  const ruleName = String(meta?.name ?? rule.name ?? '')
  if (!ruleName) return null

  const apis: string[] = []
  const strings: string[] = []
  const attackTechniques: string[] = []

  // Extract ATT&CK from meta
  const att = meta?.att ?? meta?.['att&ck'] ?? meta?.attack
  if (Array.isArray(att)) {
    for (const t of att) {
      if (typeof t === 'string') attackTechniques.push(t)
    }
  }

  // Extract features
  if (Array.isArray(features)) {
    extractFeaturesRecursive(features, apis, strings)
  }

  const category = String(meta?.scope ?? meta?.namespace ?? 'unknown')

  return {
    rule_name: ruleName,
    description: String(meta?.description ?? ''),
    apis,
    strings,
    attack_techniques: attackTechniques,
    category,
  }
}

function extractFeaturesRecursive(
  features: unknown[],
  apis: string[],
  strings: string[]
): void {
  for (const feature of features) {
    if (!feature || typeof feature !== 'object') continue
    const obj = feature as Record<string, unknown>

    if (typeof obj.api === 'string') {
      apis.push(obj.api)
    }
    if (typeof obj.string === 'string') {
      strings.push(obj.string)
    }

    // Recurse into and/or/optional
    for (const key of ['and', 'or', 'optional', 'not']) {
      if (Array.isArray(obj[key])) {
        extractFeaturesRecursive(obj[key] as unknown[], apis, strings)
      }
    }
  }
}
