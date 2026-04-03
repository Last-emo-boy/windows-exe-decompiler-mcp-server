/**
 * Safe command execution utilities.
 * Prevents command injection by avoiding shell interpolation
 * and validating command arguments against known-safe patterns.
 */

import { execFileSync, spawnSync, type SpawnSyncOptions } from 'child_process'

/**
 * Alphanumeric + limited safe characters pattern for command names.
 * Rejects shell metacharacters: ; & | ` $ ( ) { } < > ! # \n etc.
 */
const SAFE_COMMAND_NAME_RE = /^[a-zA-Z0-9._/:\\-]+$/

/**
 * Validate that a string is safe to use as a command name or path.
 * Rejects anything containing shell metacharacters.
 */
export function validateCommandName(command: string): string {
  if (!command || !SAFE_COMMAND_NAME_RE.test(command)) {
    throw new Error(
      `Unsafe command name rejected: "${command.slice(0, 80)}". ` +
      'Command names must contain only alphanumeric characters, dots, hyphens, underscores, slashes, and colons.'
    )
  }
  return command
}

/**
 * Check if a command exists in PATH without shell interpolation.
 * Uses `which` on Unix or `where.exe` on Windows (via execFileSync, NOT execSync with string).
 */
export function safeCommandExists(command: string): boolean {
  validateCommandName(command)

  const lookupCmd = process.platform === 'win32' ? 'where.exe' : 'which'
  try {
    execFileSync(lookupCmd, [command], { stdio: 'ignore', timeout: 5000 })
    return true
  } catch {
    return false
  }
}

/**
 * Safely get the version output from a command.
 * Uses spawnSync with array arguments — never shell interpolation.
 */
export function safeGetCommandVersion(
  command: string,
  versionFlag: string = '--version',
  options?: Pick<SpawnSyncOptions, 'timeout'>
): string | null {
  validateCommandName(command)

  try {
    const result = spawnSync(command, [versionFlag], {
      encoding: 'utf8',
      timeout: options?.timeout ?? 10000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    if (result.error) {
      return null
    }

    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim()
    return output || null
  } catch {
    return null
  }
}

/**
 * Validate that a Graphviz output format string is in the allowed set.
 */
const ALLOWED_GRAPHVIZ_FORMATS = new Set(['svg', 'png', 'pdf', 'dot', 'json', 'mermaid'])

export function validateGraphvizFormat(format: string): string {
  if (!ALLOWED_GRAPHVIZ_FORMATS.has(format)) {
    throw new Error(
      `Invalid Graphviz format: "${format}". Allowed: ${[...ALLOWED_GRAPHVIZ_FORMATS].join(', ')}`
    )
  }
  return format
}
