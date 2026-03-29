import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'

const repoRoot = process.cwd()
const binPath = path.join(repoRoot, 'bin', 'windows-exe-decompiler-mcp-server.js')

const printExec = spawnSync(
  process.execPath,
  [binPath, 'docker-stdio', '--print-command'],
  {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      WINDOWS_EXE_DECOMPILER_DOCKER_CONTAINER: 'integration-mcp',
    },
  }
)

assert.equal(printExec.status, 0)
assert.match(printExec.stdout.trim(), /^docker exec -i integration-mcp node dist\/index\.js$/)

const printRun = spawnSync(
  process.execPath,
  [binPath, 'docker-run', '--print-command'],
  {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      WINDOWS_EXE_DECOMPILER_DOCKER_IMAGE: 'integration-image:latest',
    },
  }
)

assert.equal(printRun.status, 0)
assert.match(printRun.stdout.trim(), /^docker run --rm -i integration-image:latest node dist\/index\.js$/)

console.log('npm docker launcher integration checks passed')
