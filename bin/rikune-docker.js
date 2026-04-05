#!/usr/bin/env node

const { runDockerLauncherCli } = await import('../dist/npm-docker-launcher.js')
const exitCode = await runDockerLauncherCli('docker-stdio', process.argv.slice(2), process.env)
process.exit(exitCode)
