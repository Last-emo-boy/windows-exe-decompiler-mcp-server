import path from 'path'
import fs from 'fs'

function resolveModuleDir(): string {
  if (typeof __dirname !== 'undefined') {
    return __dirname
  }

  const originalPrepareStackTrace = Error.prepareStackTrace
  try {
    const holder: { stack?: NodeJS.CallSite[] } = {}
    Error.prepareStackTrace = (_error, stack) => stack
    Error.captureStackTrace(holder, resolveModuleDir)
    const stack = holder.stack || []
    for (const frame of stack) {
      const fileName = frame.getFileName()
      if (fileName && /runtime-paths\.(ts|js)$/.test(fileName)) {
        return path.dirname(fileName)
      }
    }
  } finally {
    Error.prepareStackTrace = originalPrepareStackTrace
  }

  return process.cwd()
}

function resolvePackageRoot(): string {
  const candidates = [
    path.resolve(resolveModuleDir(), '..'),
    process.cwd(),
  ]

  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'package.json'))) {
      return candidate
    }
  }

  return path.resolve(resolveModuleDir(), '..')
}

const packageRoot = resolvePackageRoot()

export function getPackageRoot(): string {
  return packageRoot
}

export function resolvePackagePath(...segments: string[]): string {
  return path.join(packageRoot, ...segments)
}
