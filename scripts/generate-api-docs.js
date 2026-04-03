#!/usr/bin/env node
/**
 * generate-api-docs.js
 *
 * Scans src/index.ts for registerTool() calls, locates each tool's definition
 * and input schema in its source file, and produces a complete markdown
 * API reference at docs/API-REFERENCE.md.
 *
 * Usage:
 *   node scripts/generate-api-docs.js
 *   npm run docs:api
 */

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const ROOT = path.resolve(__dirname, '..')
const SRC = path.join(ROOT, 'src')
const INDEX_PATH = path.join(SRC, 'index.ts')
const OUTPUT_PATH = path.join(ROOT, 'docs', 'API-REFERENCE.md')

/**
 * Extract all registerTool(...Definition, ...) pairs from index.ts
 */
function extractRegistrations() {
  const content = fs.readFileSync(INDEX_PATH, 'utf-8')
  const regex = /server\.registerTool\(\s*(\w+)/g
  const definitions = []
  let match
  while ((match = regex.exec(content)) !== null) {
    definitions.push(match[1]) // e.g. "sampleIngestToolDefinition"
  }
  return definitions
}

/**
 * Find the file that exports a given definition symbol.
 */
function findDefinitionFile(symbolName, indexContent) {
  // Match: import { symbolName } from './tools/foo.js' or './workflows/bar.js'
  const re = new RegExp(`import\\s*\\{[^}]*\\b${symbolName}\\b[^}]*\\}\\s*from\\s*['"]([^'"]+)['"]`)
  const match = indexContent.match(re)
  if (!match) return null
  let relPath = match[1].replace(/\.js$/, '.ts')
  return path.join(SRC, relPath.replace(/^\.\//, ''))
}

/**
 * Extract tool name and description from a ToolDefinition const.
 */
function extractToolInfo(filePath, symbolName) {
  if (!fs.existsSync(filePath)) return null
  const content = fs.readFileSync(filePath, 'utf-8')

  // Find the const block
  const defIdx = content.indexOf(symbolName)
  if (defIdx === -1) return null

  // Extract name
  const nameMatch = content.slice(defIdx, defIdx + 2000).match(/name:\s*['"`]([^'"`]+)['"`]/)
  const descMatch = content.slice(defIdx, defIdx + 3000).match(/description:\s*\n?\s*['"`]([^'"`]+)/)
  // Try multiline description with + concatenation
  let description = descMatch?.[1] || ''
  if (!description) {
    const descBlockMatch = content.slice(defIdx, defIdx + 4000).match(
      /description:\s*\n?\s*(?:'([^']*)'|"([^"]*)")/
    )
    description = descBlockMatch?.[1] || descBlockMatch?.[2] || ''
  }

  // Extract input schema fields by looking for the InputSchema definition
  const schemaFields = extractSchemaFields(content, symbolName)

  return {
    name: nameMatch?.[1] || symbolName,
    description: description.slice(0, 200),
    file: path.relative(ROOT, filePath).replace(/\\/g, '/'),
    fields: schemaFields,
  }
}

/**
 * Extract Zod schema field names and descriptions
 */
function extractSchemaFields(content, defSymbol) {
  // Guess the input schema name from the definition symbol
  // e.g. sampleIngestToolDefinition -> SampleIngestInputSchema / sampleIngestInputSchema
  const baseName = defSymbol.replace(/ToolDefinition$/, '')
  const schemaRe = new RegExp(`(?:export\\s+)?const\\s+\\w*${baseName.replace(/^./, c => `[${c.toUpperCase()}${c.toLowerCase()}]`)}\\w*InputSchema\\s*=\\s*z\\.object\\(\\{`, 'i')
  const schemaMatch = content.match(schemaRe)
  if (!schemaMatch) return []

  const startIdx = content.indexOf(schemaMatch[0])
  // Find balanced braces
  let depth = 0
  let blockStart = -1
  for (let i = startIdx; i < content.length && i < startIdx + 5000; i++) {
    if (content[i] === '{') {
      if (depth === 0) blockStart = i
      depth++
    }
    if (content[i] === '}') {
      depth--
      if (depth === 0) {
        const block = content.slice(blockStart + 1, i)
        return parseZodFields(block)
      }
    }
  }
  return []
}

function parseZodFields(block) {
  const fields = []
  // Match field_name: z.xxx().describe('...')
  const fieldRe = /(\w+)\s*:\s*z\.(\w+)\([^)]*\)(?:\.[^.]*)*?\.describe\(\s*['"`]([^'"`]+)['"`]\s*\)/g
  let m
  while ((m = fieldRe.exec(block)) !== null) {
    fields.push({
      name: m[1],
      type: m[2],
      description: m[3],
    })
  }
  // Also match fields without describe
  const simpleRe = /(\w+)\s*:\s*z\.(\w+)\(/g
  while ((m = simpleRe.exec(block)) !== null) {
    if (!fields.find(f => f.name === m[1])) {
      fields.push({
        name: m[1],
        type: m[2],
        description: '',
      })
    }
  }
  return fields
}

// --- Main ---

const indexContent = fs.readFileSync(INDEX_PATH, 'utf-8')
const registrations = extractRegistrations()

const tools = []
for (const defSymbol of registrations) {
  const filePath = findDefinitionFile(defSymbol, indexContent)
  if (!filePath) continue
  const info = extractToolInfo(filePath, defSymbol)
  if (info) tools.push(info)
}

// Categorize tools by directory/prefix
const categories = new Map()
for (const tool of tools) {
  const prefix = tool.name.split('.')[0]
  if (!categories.has(prefix)) categories.set(prefix, [])
  categories.get(prefix).push(tool)
}

// Generate markdown
const lines = [
  '# API Reference',
  '',
  `> Auto-generated on ${new Date().toISOString().split('T')[0]} from ${tools.length} registered tools.`,
  `> Run \`npm run docs:api\` to regenerate.`,
  '',
  '## Table of Contents',
  '',
]

for (const [cat] of categories) {
  lines.push(`- [${cat}.*](#${cat})`)
}

lines.push('', '---', '')

for (const [cat, catTools] of categories) {
  lines.push(`## ${cat}`, '')
  for (const tool of catTools) {
    lines.push(`### \`${tool.name}\``, '')
    if (tool.description) {
      lines.push(tool.description, '')
    }
    lines.push(`**Source:** \`${tool.file}\``, '')
    if (tool.fields.length > 0) {
      lines.push('| Parameter | Type | Description |')
      lines.push('|-----------|------|-------------|')
      for (const f of tool.fields) {
        lines.push(`| \`${f.name}\` | ${f.type} | ${f.description} |`)
      }
      lines.push('')
    }
  }
}

lines.push('', '---', `*Generated by scripts/generate-api-docs.js*`)

fs.writeFileSync(OUTPUT_PATH, lines.join('\n'), 'utf-8')
console.log(`Generated ${OUTPUT_PATH} with ${tools.length} tools in ${categories.size} categories.`)
