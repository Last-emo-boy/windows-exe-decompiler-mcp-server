#!/usr/bin/env node
// Read-only source authority check used by the independent static OCI publisher.
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

const SHA = /^[0-9a-f]{40}$/

function execute(command, args, env) {
  const result = spawnSync(command, args, { env, encoding: 'utf8', timeout: 30_000 })
  // Never echo command stderr: authentication helpers may include credential data.
  if (result.error || result.status !== 0) throw new Error(`${command} source verification failed`)
  return result.stdout.trim()
}

export function verifyStaticSource(env = process.env, run = execute) {
  const revision = env.GITHUB_SHA ?? ''
  if (!SHA.test(revision) || env.GITHUB_REF !== 'refs/heads/main' ||
      env.GITHUB_REPOSITORY?.toLowerCase() !== 'last-emo-boy/rikune') {
    throw new Error('static publication requires the exact Rikune main revision')
  }
  const loom = new URL(env.LOOM_REPOSITORY_URL ?? 'https://git.w33d.xyz/git/w33d/rikune.git')
  if (loom.origin !== 'https://git.w33d.xyz' || loom.username || loom.password || loom.search || loom.hash ||
      !/^\/git\/[A-Za-z0-9_-]{1,128}\/(?:rikune|Rikune)\.git$/.test(loom.pathname)) {
    throw new Error('Loom source URL is outside the Rikune repository scope')
  }
  const gitEnv = { ...env, GIT_TERMINAL_PROMPT: '0' }
  if (run('git', ['rev-parse', 'HEAD'], gitEnv) !== revision ||
      run('git', ['status', '--porcelain'], gitEnv) !== '') {
    throw new Error('static publication checkout is not the exact clean revision')
  }
  const githubMain = run('gh', ['api', 'repos/Last-emo-boy/rikune/git/ref/heads/main',
                               '--jq', '.object.sha'], env)
  // An authenticated clone probe must not follow a redirect to another origin.
  const loomEnv = { ...gitEnv, GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.followRedirects', GIT_CONFIG_VALUE_0: 'false' }
  if (env.LOOM_READ_TOKEN) {
    const username = env.LOOM_READ_USERNAME ?? 'w33d'
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(username) || /[\r\n\0]/.test(env.LOOM_READ_TOKEN)) {
      throw new Error('invalid Loom read credential configuration')
    }
    // Keep the secret out of URLs, argv, and the public source evidence.
    loomEnv.GIT_CONFIG_COUNT = '2'
    loomEnv.GIT_CONFIG_KEY_1 = 'http.https://git.w33d.xyz/.extraheader'
    loomEnv.GIT_CONFIG_VALUE_1 = 'Authorization: Basic ' +
      Buffer.from(username + ':' + env.LOOM_READ_TOKEN).toString('base64')
  }
  const advertised = run('git', ['ls-remote', loom.toString(), 'refs/heads/main'], loomEnv)
  const rows = advertised.split(/\r?\n/).filter(Boolean)
  const fields = rows.length === 1 ? rows[0].split(/\s+/) : []
  if (githubMain !== revision || fields.length !== 2 || fields[0] !== revision || fields[1] !== 'refs/heads/main') {
    throw new Error('Loom and GitHub main must both equal the publication revision')
  }
  return { schema_version: 1, source_repository: 'https://github.com/Last-emo-boy/rikune',
    source_revision: revision, github_main: githubMain, loom_main: fields[0],
    loom_repository_url: loom.toString(), verified_at: new Date().toISOString() }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.stdout.write(JSON.stringify(verifyStaticSource(), null, 2) + '\n')
  } catch (error) {
    process.stderr.write((error instanceof Error ? error.message : 'source verification failed') + '\n')
    process.exitCode = 1
  }
}
