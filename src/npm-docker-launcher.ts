import { spawn, spawnSync } from 'node:child_process'

export type DockerLauncherMode = 'docker-stdio' | 'docker-run'

export interface DockerLauncherConfig {
  mode: DockerLauncherMode
  command: string
  args: string[]
  description: string
  containerName: string
  imageName: string
}

export interface DockerLauncherCliOptions {
  printCommand: boolean
  skipPreflight: boolean
  help: boolean
}

export function buildDockerLauncherConfig(
  mode: DockerLauncherMode,
  env: NodeJS.ProcessEnv = process.env
): DockerLauncherConfig {
  const containerName =
    env.RIKUNE_DOCKER_CONTAINER || 'rikune'
  const imageName =
    env.RIKUNE_DOCKER_IMAGE || 'rikune:latest'

  if (mode === 'docker-run') {
    return {
      mode,
      command: 'docker',
      args: ['run', '--rm', '-i', imageName, 'node', 'dist/index.js'],
      description: 'Launch a fresh MCP worker from the Docker image',
      containerName,
      imageName,
    }
  }

  return {
    mode,
    command: 'docker',
    args: ['exec', '-i', containerName, 'node', 'dist/index.js'],
    description: 'Attach stdio MCP to the long-lived Docker compose container',
    containerName,
    imageName,
  }
}

export function parseDockerLauncherCliArgs(argv: string[]): {
  options: DockerLauncherCliOptions
  passthroughArgs: string[]
} {
  const options: DockerLauncherCliOptions = {
    printCommand: false,
    skipPreflight: false,
    help: false,
  }
  const passthroughArgs: string[] = []

  for (const arg of argv) {
    switch (arg) {
      case '--help':
      case '-h':
        options.help = true
        break
      case '--print-command':
        options.printCommand = true
        break
      case '--skip-preflight':
        options.skipPreflight = true
        break
      default:
        passthroughArgs.push(arg)
        break
    }
  }

  return { options, passthroughArgs }
}

function isDockerAvailable(): boolean {
  const probe = spawnSync('docker', ['version'], {
    stdio: 'ignore',
    shell: false,
  })
  return !probe.error && probe.status === 0
}

function isContainerRunning(containerName: string): boolean {
  const probe = spawnSync(
    'docker',
    ['ps', '--filter', `name=^/${containerName}$`, '--format', '{{.Names}}'],
    {
      encoding: 'utf8',
      shell: false,
    }
  )

  if (probe.error || probe.status !== 0) {
    return false
  }

  return probe.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .includes(containerName)
}

export function formatDockerLauncherHelp(mode: DockerLauncherMode): string {
  const modeText =
    mode === 'docker-run' ? 'docker-run' : 'docker-stdio'

  return [
    `rikune ${modeText}`,
    '',
    'Published-package launcher mode that keeps npm and Docker separate:',
    '- npm provides the client-side executable and versioned launcher',
    '- Docker provides the heavy reverse-engineering runtime',
    '',
    'Usage:',
    `  npx -y rikune ${modeText}`,
    '',
    'Options:',
    '  --print-command   Print the resolved docker command and exit',
    '  --skip-preflight  Skip docker/container availability checks',
    '  -h, --help        Show this help',
    '',
    'Environment:',
    '  RIKUNE_DOCKER_CONTAINER  Override compose container name',
    '  RIKUNE_DOCKER_IMAGE      Override docker image name',
    '',
    'Recommended runtime:',
    '  docker compose up -d mcp-server',
    '',
    'Recommended MCP client config:',
    '  command: "npx"',
    `  args: ["-y", "rikune", "${modeText}"]`,
  ].join('\n')
}

function buildPreflightError(mode: DockerLauncherMode, config: DockerLauncherConfig): string {
  if (mode === 'docker-run') {
    return [
      `Docker image '${config.imageName}' is required for npm docker-run mode.`,
      `Build or pull it first, for example: docker pull ghcr.io/last-emo-boy/rikune:latest`,
      `Or build locally: docker build -t ${config.imageName} .`,
    ].join('\n')
  }

  return [
    `Docker compose container '${config.containerName}' is not running.`,
    'This npm launcher intentionally keeps npm and Docker separated but strongly bound:',
    '- npm supplies the MCP launcher',
    '- Docker compose supplies the long-lived runtime, storage, and upload API',
    '',
    'Start the daemon first:',
    '  docker compose up -d mcp-server',
    '',
    'Then point your MCP client at:',
    '  npx -y rikune docker-stdio',
  ].join('\n')
}

export async function runDockerLauncherCli(
  mode: DockerLauncherMode,
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): Promise<number> {
  const { options, passthroughArgs } = parseDockerLauncherCliArgs(argv)

  if (options.help) {
    process.stdout.write(formatDockerLauncherHelp(mode) + '\n')
    return 0
  }

  if (passthroughArgs.length > 0) {
    process.stderr.write(
      `Unexpected arguments for ${mode}: ${passthroughArgs.join(' ')}\n` +
        'Use --help for supported options.\n'
    )
    return 2
  }

  const config = buildDockerLauncherConfig(mode, env)

  if (options.printCommand) {
    process.stdout.write([config.command, ...config.args].join(' ') + '\n')
    return 0
  }

  if (!options.skipPreflight && !isDockerAvailable()) {
    process.stderr.write(
      'Docker is required for the published npm launcher but was not found or is not running.\n'
    )
    return 1
  }

  if (!options.skipPreflight && mode === 'docker-stdio' && !isContainerRunning(config.containerName)) {
    process.stderr.write(buildPreflightError(mode, config) + '\n')
    return 1
  }

  return await new Promise<number>(resolve => {
    const child = spawn(config.command, config.args, {
      stdio: 'inherit',
      env,
      shell: false,
    })

    child.on('error', error => {
      process.stderr.write(
        `Failed to launch Docker runtime for ${mode}: ${error.message}\n`
      )
      resolve(1)
    })

    child.on('exit', code => {
      resolve(code ?? 1)
    })
  })
}
