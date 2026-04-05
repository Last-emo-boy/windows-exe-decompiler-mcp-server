import { describe, expect, test } from '@jest/globals'
import {
  buildDockerLauncherConfig,
  formatDockerLauncherHelp,
  parseDockerLauncherCliArgs,
} from '../../src/npm-docker-launcher.js'

describe('npm docker launcher', () => {
  test('builds docker exec config for published-package stdio mode', () => {
    const config = buildDockerLauncherConfig('docker-stdio', {
      RIKUNE_DOCKER_CONTAINER: 'custom-mcp',
    } as NodeJS.ProcessEnv)

    expect(config.command).toBe('docker')
    expect(config.args).toEqual(['exec', '-i', 'custom-mcp', 'node', 'dist/index.js'])
    expect(config.containerName).toBe('custom-mcp')
    expect(config.imageName).toBe('rikune:latest')
  })

  test('builds docker run config when explicitly requested', () => {
    const config = buildDockerLauncherConfig('docker-run', {
      RIKUNE_DOCKER_IMAGE: 'custom-image:dev',
    } as NodeJS.ProcessEnv)

    expect(config.args).toEqual(['run', '--rm', '-i', 'custom-image:dev', 'node', 'dist/index.js'])
    expect(config.imageName).toBe('custom-image:dev')
  })

  test('parses launcher cli options without consuming unknown args silently', () => {
    const parsed = parseDockerLauncherCliArgs(['--print-command', '--skip-preflight', 'unexpected'])

    expect(parsed.options.printCommand).toBe(true)
    expect(parsed.options.skipPreflight).toBe(true)
    expect(parsed.passthroughArgs).toEqual(['unexpected'])
  })

  test('help text explains npm plus docker split', () => {
    const help = formatDockerLauncherHelp('docker-stdio')

    expect(help).toContain('npx -y rikune docker-stdio')
    expect(help).toContain('npm provides the client-side executable')
    expect(help).toContain('Docker provides the heavy reverse-engineering runtime')
  })
})
