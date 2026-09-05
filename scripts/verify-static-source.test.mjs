import assert from 'node:assert/strict'
import test from 'node:test'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import { spawnSync } from 'node:child_process'

import { verifyStaticSource } from './verify-static-source.mjs'

const revision = 'a'.repeat(40)
const environment = { GITHUB_SHA: revision, GITHUB_REF: 'refs/heads/main', GITHUB_REPOSITORY: 'Last-emo-boy/rikune' }

function fixture(overrides = {}) {
  const calls = []
  const run = (command, args, env) => {
    calls.push({ command, args, env })
    if (command === 'gh') return overrides.github ?? revision
    if (args[0] === 'rev-parse') return overrides.head ?? revision
    if (args[0] === 'status') return overrides.dirty ?? ''
    if (args[0] === 'ls-remote') return overrides.loom ?? `${revision}\trefs/heads/main`
    throw new Error('unexpected source command')
  }
  return { run, calls }
}

test('both exact main refs and clean checkout are required', () => {
  const { run, calls } = fixture()
  const proof = verifyStaticSource(environment, run)
  assert.equal(proof.loom_main, revision)
  assert.equal(proof.github_main, revision)
  assert.equal(calls.length, 4)
  assert(calls.every(call => !call.args.includes('push')))
})

test('missing, divergent, ambiguous, or dirty sources fail closed', () => {
  for (const overrides of [{ loom: '' }, { github: 'b'.repeat(40) }, { head: 'b'.repeat(40) },
    { dirty: ' M src/index.ts' }, { loom: `${revision}\trefs/heads/main\n${revision}\trefs/heads/main` }]) {
    assert.throws(() => verifyStaticSource(environment, fixture(overrides).run))
  }
  for (const env of [{ ...environment, GITHUB_REF: 'refs/tags/v1.4.1' },
    { ...environment, LOOM_REPOSITORY_URL: 'https://attacker.invalid/git/w33d/rikune.git' },
    { ...environment, LOOM_REPOSITORY_URL: 'https://user:secret@git.w33d.xyz/git/w33d/rikune.git' }]) {
    assert.throws(() => verifyStaticSource(env, fixture().run))
  }
})

test('optional private Loom read credential is scoped and absent from argv and evidence', () => {
  const { run, calls } = fixture()
  const token = 'unit-only-read-token-' + 'x'.repeat(32)
  const proof = verifyStaticSource({ ...environment, LOOM_READ_TOKEN: token }, run)
  const request = calls.find(call => call.args[0] === 'ls-remote')
  assert.equal(request.env.GIT_CONFIG_KEY_0, 'http.followRedirects')
  assert.equal(request.env.GIT_CONFIG_VALUE_0, 'false')
  assert.equal(request.env.GIT_CONFIG_KEY_1, 'http.https://git.w33d.xyz/.extraheader')
  assert(request.env.GIT_CONFIG_VALUE_1.startsWith('Authorization: Basic '))
  assert(!JSON.stringify(calls.map(call => call.args)).includes(token))
  assert(!JSON.stringify(proof).includes(token))
})

test('static workflow signs only after mirror and runtime verification and never publishes npm aliases', () => {
  const require = createRequire(import.meta.url)
  const yaml = require('js-yaml')
  const source = fs.readFileSync(new URL('../.github/workflows/publish-static.yml', import.meta.url), 'utf8')
  const workflow = yaml.load(source)
  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch'])
  const steps = workflow.jobs.static.steps
  const at = name => steps.findIndex(step => step.name === name)
  assert(at('Verify clean mirrored main before build') < at('Build and push the static candidate'))
  assert(at('Recheck mirrored main before signing') < at('Attest build provenance'))
  assert(at('Verify the published immutable static image') < at('Attest build provenance'))
  assert(at('Sign and verify the exact image digest') < at('Upload verified static evidence'))
  const checks = steps.find(step => step.name === 'Build and test the corrected static source').run
  assert(checks.split('\n').includes('test -z "$(git status --porcelain)"'))
  assert(!/npm\s+publish|git\s+tag|:latest\b/.test(source))
  for (const step of steps) {
    if (step.uses) assert(/@[0-9a-f]{40}$/.test(step.uses))
    if (step.run) {
      const result = spawnSync('bash', ['-n'], { input: step.run, encoding: 'utf8' })
      assert.equal(result.status, 0, step.name + ': ' + result.stderr)
    }
  }
})
