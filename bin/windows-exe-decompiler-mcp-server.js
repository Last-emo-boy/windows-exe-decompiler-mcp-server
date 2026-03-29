#!/usr/bin/env node

const rawArgs = process.argv.slice(2)
const subcommand = rawArgs[0]

if (subcommand === 'docker-stdio' || subcommand === 'docker-run') {
  const { runDockerLauncherCli } = await import('../dist/npm-docker-launcher.js')
  const exitCode = await runDockerLauncherCli(subcommand, rawArgs.slice(1), process.env)
  process.exit(exitCode)
}

await import('../dist/index.js')
