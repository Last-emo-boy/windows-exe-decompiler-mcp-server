/**
 * GDB/MI protocol client — manages a GDB subprocess with MI interface.
 */

import { spawn, type ChildProcess } from 'child_process'
import { EventEmitter } from 'events'

export interface MiResponse {
  type: 'result' | 'exec' | 'notify' | 'console' | 'target' | 'log'
  class_: string // 'done', 'running', 'stopped', 'error', etc.
  payload: Record<string, unknown>
  raw: string
}

export class GdbMiClient extends EventEmitter {
  private process: ChildProcess | null = null
  private buffer = ''
  private commandQueue: Array<{
    token: number
    resolve: (resp: MiResponse) => void
    reject: (err: Error) => void
    timer: ReturnType<typeof setTimeout>
  }> = []
  private nextToken = 1
  private _exited = false

  get exited(): boolean {
    return this._exited
  }

  /**
   * Spawn GDB with MI interface.
   * @param binaryPath Path to binary to debug
   * @param gdbPath Path to gdb executable (default: 'gdb')
   * @param extraArgs Additional GDB arguments
   */
  async start(
    binaryPath: string,
    gdbPath = 'gdb',
    extraArgs: string[] = []
  ): Promise<MiResponse> {
    const args = ['--interpreter=mi', '--quiet', ...extraArgs, binaryPath]
    this.process = spawn(gdbPath, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    this.process.stdout!.on('data', (data: Buffer) => {
      this.buffer += data.toString()
      this.processBuffer()
    })

    this.process.stderr!.on('data', (data: Buffer) => {
      this.emit('log', data.toString())
    })

    this.process.on('exit', (code) => {
      this._exited = true
      this.emit('exit', code)
      // Reject pending commands
      for (const cmd of this.commandQueue) {
        clearTimeout(cmd.timer)
        cmd.reject(new Error(`GDB exited with code ${code}`))
      }
      this.commandQueue = []
    })

    this.process.on('error', (err) => {
      this._exited = true
      this.emit('error', err)
    })

    // Wait for initial prompt
    return new Promise((resolve) => {
      const handler = (resp: MiResponse) => {
        if (resp.type === 'notify' || resp.type === 'result') {
          this.removeListener('response', handler)
          resolve(resp)
        }
      }
      this.on('response', handler)
      // Fallback: resolve after a short delay if no MI response
      setTimeout(() => {
        this.removeListener('response', handler)
        resolve({ type: 'result', class_: 'done', payload: {}, raw: '(gdb)' })
      }, 2000)
    })
  }

  /**
   * Send an MI command and wait for result.
   */
  async command(cmd: string, timeoutMs = 30000): Promise<MiResponse> {
    if (!this.process || this._exited) {
      throw new Error('GDB process not running')
    }

    const token = this.nextToken++
    const fullCmd = `${token}${cmd}\n`

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.commandQueue.findIndex((c) => c.token === token)
        if (idx !== -1) this.commandQueue.splice(idx, 1)
        reject(new Error(`GDB command timed out after ${timeoutMs}ms: ${cmd}`))
      }, timeoutMs)

      this.commandQueue.push({ token, resolve, reject, timer })
      this.process!.stdin!.write(fullCmd)
    })
  }

  /**
   * Kill the GDB process.
   */
  kill(): void {
    if (this.process && !this._exited) {
      try {
        this.process.stdin!.write('-gdb-exit\n')
      } catch {
        // stdin may already be closed
      }
      setTimeout(() => {
        if (!this._exited && this.process) {
          this.process.kill('SIGKILL')
        }
      }, 2000)
    }
  }

  private processBuffer(): void {
    const lines = this.buffer.split('\n')
    this.buffer = lines.pop() || ''

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed || trimmed === '(gdb)') continue

      const resp = this.parseMiLine(trimmed)
      if (resp) {
        this.emit('response', resp)

        // Match result responses to pending commands
        if (resp.type === 'result') {
          const tokenMatch = trimmed.match(/^(\d+)\^/)
          if (tokenMatch) {
            const tok = parseInt(tokenMatch[1], 10)
            const idx = this.commandQueue.findIndex((c) => c.token === tok)
            if (idx !== -1) {
              const cmd = this.commandQueue.splice(idx, 1)[0]
              clearTimeout(cmd.timer)
              if (resp.class_ === 'error') {
                cmd.reject(new Error(String(resp.payload.msg || 'GDB error')))
              } else {
                cmd.resolve(resp)
              }
            }
          }
        }

        // Emit async exec events (stopped, running)
        if (resp.type === 'exec') {
          this.emit('exec', resp)
        }
      }
    }
  }

  private parseMiLine(line: string): MiResponse | null {
    // Result: token^class,payload
    const resultMatch = line.match(/^(\d*)\^(\w+)(?:,(.*))?$/)
    if (resultMatch) {
      return {
        type: 'result',
        class_: resultMatch[2],
        payload: resultMatch[3] ? this.parsePayload(resultMatch[3]) : {},
        raw: line,
      }
    }

    // Exec async: *class,payload
    const execMatch = line.match(/^\*(\w+)(?:,(.*))?$/)
    if (execMatch) {
      return {
        type: 'exec',
        class_: execMatch[1],
        payload: execMatch[2] ? this.parsePayload(execMatch[2]) : {},
        raw: line,
      }
    }

    // Notify async: =class,payload
    const notifyMatch = line.match(/^=(\w+)(?:,(.*))?$/)
    if (notifyMatch) {
      return {
        type: 'notify',
        class_: notifyMatch[1],
        payload: notifyMatch[2] ? this.parsePayload(notifyMatch[2]) : {},
        raw: line,
      }
    }

    // Console output: ~"string"
    if (line.startsWith('~"')) {
      return { type: 'console', class_: 'output', payload: { text: this.unquote(line.slice(1)) }, raw: line }
    }

    // Target output: @"string"
    if (line.startsWith('@"')) {
      return { type: 'target', class_: 'output', payload: { text: this.unquote(line.slice(1)) }, raw: line }
    }

    // Log output: &"string"
    if (line.startsWith('&"')) {
      return { type: 'log', class_: 'output', payload: { text: this.unquote(line.slice(1)) }, raw: line }
    }

    return null
  }

  private parsePayload(str: string): Record<string, unknown> {
    // Simplified MI payload parser — handles key=value and key="value"
    const result: Record<string, unknown> = {}
    let remaining = str
    while (remaining.length > 0) {
      const eqIdx = remaining.indexOf('=')
      if (eqIdx === -1) break

      const key = remaining.slice(0, eqIdx).trim()
      remaining = remaining.slice(eqIdx + 1)

      if (remaining.startsWith('"')) {
        // Quoted string value
        let end = 1
        while (end < remaining.length) {
          if (remaining[end] === '\\') {
            end += 2
            continue
          }
          if (remaining[end] === '"') break
          end++
        }
        result[key] = remaining.slice(1, end).replace(/\\"/g, '"').replace(/\\n/g, '\n')
        remaining = remaining.slice(end + 1)
        if (remaining.startsWith(',')) remaining = remaining.slice(1)
      } else if (remaining.startsWith('{')) {
        // Nested object — find matching brace
        let depth = 0
        let end = 0
        for (; end < remaining.length; end++) {
          if (remaining[end] === '{') depth++
          if (remaining[end] === '}') depth--
          if (depth === 0) break
        }
        result[key] = remaining.slice(0, end + 1)
        remaining = remaining.slice(end + 1)
        if (remaining.startsWith(',')) remaining = remaining.slice(1)
      } else if (remaining.startsWith('[')) {
        let depth = 0
        let end = 0
        for (; end < remaining.length; end++) {
          if (remaining[end] === '[') depth++
          if (remaining[end] === ']') depth--
          if (depth === 0) break
        }
        result[key] = remaining.slice(0, end + 1)
        remaining = remaining.slice(end + 1)
        if (remaining.startsWith(',')) remaining = remaining.slice(1)
      } else {
        const commaIdx = remaining.indexOf(',')
        if (commaIdx === -1) {
          result[key] = remaining.trim()
          break
        } else {
          result[key] = remaining.slice(0, commaIdx).trim()
          remaining = remaining.slice(commaIdx + 1)
        }
      }
    }
    return result
  }

  private unquote(s: string): string {
    if (s.startsWith('"') && s.endsWith('"')) {
      return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\t/g, '\t')
    }
    return s
  }
}
