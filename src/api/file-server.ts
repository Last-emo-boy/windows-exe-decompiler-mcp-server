/**
 * HTTP File Server
 * Embedded HTTP server for upload sessions, artifact download, and direct sample upload.
 */

import fs from 'fs/promises'
import http, { type IncomingMessage, type ServerResponse } from 'http'
import path from 'path'
import { logger } from '../logger.js'
import { AuthMiddleware } from './auth-middleware.js'
import { handleHealthCheck } from './routes/health.js'
import { parseMultipart } from './multipart-parser.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { DatabaseManager, UploadSession } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { SampleFinalizationService } from '../sample-finalization.js'
import { RateLimiter } from './rate-limiter.js'
import { handleSseConnection } from './sse-events.js'
import { handleDashboardApi } from './routes/dashboard-api.js'

export interface FileServerConfig {
  port: number
  apiKey?: string
  maxFileSize: number
}

export interface FileServerDependencies {
  storageManager: StorageManager
  database: DatabaseManager
  workspaceManager: WorkspaceManager
  finalizationService: SampleFinalizationService
}

class HttpRequestError extends Error {
  constructor(
    public readonly status: number,
    public readonly errorLabel: string,
    message: string
  ) {
    super(message)
    this.name = 'HttpRequestError'
  }
}

export class FileServer {
  private server: http.Server | null = null
  private effectivePort: number
  private readonly authMiddleware: AuthMiddleware
  private readonly rateLimiter: RateLimiter

  constructor(
    private readonly config: FileServerConfig,
    private readonly dependencies: FileServerDependencies
  ) {
    this.effectivePort = config.port
    this.authMiddleware = new AuthMiddleware({
      apiKey: config.apiKey,
      enabled: Boolean(config.apiKey),
    })
    this.rateLimiter = new RateLimiter()
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        void this.handleRequest(req, res)
      })

      this.server.on('error', reject)
      this.server.listen(this.config.port, '0.0.0.0', () => {
        const address = this.server?.address()
        if (address && typeof address !== 'string') {
          this.effectivePort = address.port
        }
        logger.info({ port: this.effectivePort }, 'HTTP File Server started')
        resolve()
      })
    })
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      if (!this.server) {
        resolve()
        return
      }
      this.server.close((error) => {
        if (error) {
          reject(error)
          return
        }
        logger.info('HTTP File Server stopped')
        this.server = null
        this.rateLimiter.destroy()
        resolve()
      })
    })
  }

  getPort(): number {
    return this.effectivePort
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://127.0.0.1:${this.effectivePort || this.config.port}`)
    const pathname = url.pathname

    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    // Rate limiting
    if (!this.rateLimiter.check(req, res)) {
      return
    }

    try {
      // ── Dashboard (static HTML + API) ─────────────────────────
      if ((pathname === '/dashboard' || pathname === '/') && req.method === 'GET') {
        await this.serveDashboardHtml(res)
        return
      }

      if (pathname.startsWith('/api/v1/dashboard') && req.method === 'GET') {
        handleDashboardApi(res, pathname, url.searchParams)
        return
      }

      if (pathname === '/api/v1/health' && req.method === 'GET') {
        await handleHealthCheck(res, '1.0.0-beta.2')
        return
      }

      if (pathname === '/api/v1/events' && req.method === 'GET') {
        handleSseConnection(req, res, url.searchParams)
        return
      }

      if (pathname === '/api/v1/samples' && req.method === 'POST') {
        await this.handleDirectSampleUpload(req, res)
        return
      }

      if (pathname.startsWith('/api/v1/samples/') && req.method === 'GET') {
        const sampleId = decodeURIComponent(pathname.split('/').pop() || '')
        await this.handleSampleGet(req, res, sampleId, url.searchParams.get('download') === 'true')
        return
      }

      if (pathname === '/api/v1/artifacts' && req.method === 'GET') {
        await this.handleArtifactsList(req, res, url.searchParams.get('sample_id'))
        return
      }

      if (pathname.startsWith('/api/v1/artifacts/') && req.method === 'GET') {
        const artifactId = decodeURIComponent(pathname.split('/').pop() || '')
        await this.handleArtifactGet(req, res, artifactId, url.searchParams.get('download') === 'true')
        return
      }

      if (pathname.startsWith('/api/v1/artifacts/') && req.method === 'DELETE') {
        const artifactId = decodeURIComponent(pathname.split('/').pop() || '')
        await this.handleArtifactDelete(req, res, artifactId)
        return
      }

      if (pathname.startsWith('/api/v1/uploads/') && req.method === 'POST') {
        const token = this.extractTokenFromPath(pathname)
        await this.handleSessionUpload(req, res, token)
        return
      }

      if (pathname.startsWith('/api/v1/uploads/') && req.method === 'GET') {
        const token = this.extractTokenFromPath(pathname)
        await this.handleSessionStatus(res, token)
        return
      }

      if (pathname === '/upload' && req.method === 'POST') {
        await this.handleSessionUpload(req, res, url.searchParams.get('token'))
        return
      }

      if (pathname === '/status' && req.method === 'GET') {
        await this.handleSessionStatus(res, url.searchParams.get('token'))
        return
      }

      this.sendJson(res, 404, { error: 'Not found' })
    } catch (error) {
      if (error instanceof HttpRequestError) {
        this.sendJson(res, error.status, {
          error: error.errorLabel,
          message: error.message,
        })
        return
      }

      logger.error({ err: error }, 'HTTP File Server request failed')
      this.sendJson(res, 500, {
        error: 'Internal Server Error',
        message: (error as Error).message,
      })
    }
  }

  private async serveDashboardHtml(res: ServerResponse): Promise<void> {
    try {
      const { fileURLToPath } = await import('url')
      const thisDir = path.dirname(fileURLToPath(import.meta.url))
      const htmlPath = path.join(thisDir, 'dashboard', 'index.html')
      const html = await fs.readFile(htmlPath, 'utf-8')
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(html)
    } catch {
      res.writeHead(500, { 'Content-Type': 'text/plain' })
      res.end('Dashboard HTML not found')
    }
  }

  private requireApiKey(req: IncomingMessage, res: ServerResponse): boolean {
    if (this.authMiddleware.validateApiKey(req.headers)) {
      return true
    }

    const authError = this.authMiddleware.getAuthError(Boolean(req.headers['x-api-key']))
    res.writeHead(authError.status, { 'Content-Type': 'application/json' })
    res.end(authError.body)
    return false
  }

  private sendJson(res: ServerResponse, status: number, payload: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(payload))
  }

  private sendBuffer(
    res: ServerResponse,
    status: number,
    body: Buffer,
    contentType = 'application/octet-stream',
    filename?: string
  ): void {
    const headers: Record<string, string | number> = {
      'Content-Type': contentType,
      'Content-Length': body.length,
    }
    if (filename) {
      headers['Content-Disposition'] = `attachment; filename="${filename.replace(/"/g, '_')}"`
    }
    res.writeHead(status, headers)
    res.end(body)
  }

  private async readBody(req: IncomingMessage): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = []
      let totalSize = 0
      let settled = false

      const fail = (error: Error) => {
        if (settled) {
          return
        }
        settled = true
        reject(error)
      }

      req.on('data', (chunk: Buffer) => {
        totalSize += chunk.length
        if (totalSize > this.config.maxFileSize) {
          fail(
            new HttpRequestError(
              413,
              'Payload Too Large',
              `File size ${totalSize} exceeds limit ${this.config.maxFileSize}`
            )
          )
          req.removeAllListeners('data')
          req.resume()
          return
        }
        chunks.push(chunk)
      })

      req.on('end', () => {
        if (settled) {
          return
        }
        settled = true
        resolve(Buffer.concat(chunks))
      })

      req.on('error', (error) => {
        fail(
          error instanceof HttpRequestError
            ? error
            : new HttpRequestError(400, 'Bad Request', error.message)
        )
      })
    })
  }

  private extractTokenFromPath(pathname: string): string | null {
    const parts = pathname.split('/').filter(Boolean)
    if (parts.length === 0) {
      return null
    }
    if (parts[parts.length - 1] === 'status' && parts.length >= 2) {
      return parts[parts.length - 2] || null
    }
    return parts[parts.length - 1] || null
  }

  private validateSession(token: string | null): UploadSession | null {
    if (!token) {
      return null
    }

    this.dependencies.database.expireUploadSessions()
    const session = this.dependencies.database.findUploadSessionByToken(token)
    if (!session) {
      return null
    }

    if (
      session.status !== 'registered' &&
      new Date(session.expires_at).getTime() < Date.now()
    ) {
      this.dependencies.database.markUploadSessionExpired(token)
      return this.dependencies.database.findUploadSessionByToken(token) || null
    }

    return session
  }

  private async resolveArtifactPath(sampleId: string, relativePath: string): Promise<string> {
    const workspace = await this.dependencies.workspaceManager.getWorkspace(sampleId)
    return this.dependencies.workspaceManager.normalizePath(workspace.root, relativePath)
  }

  private async resolveOriginalSamplePath(sampleId: string): Promise<string | null> {
    const workspace = await this.dependencies.workspaceManager.getWorkspace(sampleId)
    const entries = await fs.readdir(workspace.original)
    const file = entries[0]
    return file ? path.join(workspace.original, file) : null
  }

  private async handleDirectSampleUpload(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.requireApiKey(req, res)) {
      return
    }

    const contentType = req.headers['content-type'] || ''
    if (!contentType.includes('multipart/form-data')) {
      this.sendJson(res, 400, {
        error: 'Bad Request',
        message: 'Content-Type must be multipart/form-data',
      })
      return
    }

    const body = await this.readBody(req)
    let multipart
    try {
      multipart = parseMultipart(body, contentType)
    } catch (error) {
      throw new HttpRequestError(400, 'Bad Request', (error as Error).message)
    }

    const file = multipart.files.find((item) => item.fieldname === 'file')
    if (!file) {
      this.sendJson(res, 400, {
        error: 'Bad Request',
        message: 'No file uploaded',
      })
      return
    }

    const filename = multipart.fields.filename || file.filename
    const source = multipart.fields.source || 'api_upload'
    const finalized = await this.dependencies.finalizationService.finalizeBuffer({
      data: file.data,
      filename,
      source,
      auditOperation: 'api.sample_upload',
    })

    this.sendJson(res, 201, {
      ok: true,
      data: {
        sample_id: finalized.sample_id,
        filename,
        size: finalized.size,
        uploaded_at: new Date().toISOString(),
        existed: finalized.existed,
        file_type: finalized.file_type,
      },
    })
  }

  private async handleSampleGet(
    req: IncomingMessage,
    res: ServerResponse,
    sampleId: string,
    download: boolean
  ): Promise<void> {
    if (!this.requireApiKey(req, res)) {
      return
    }

    const sample = this.dependencies.database.findSample(sampleId)
    if (!sample) {
      this.sendJson(res, 404, {
        error: 'Not Found',
        message: `Sample not found: ${sampleId}`,
      })
      return
    }

    if (download) {
      const samplePath = await this.resolveOriginalSamplePath(sampleId)
      if (!samplePath) {
        this.sendJson(res, 404, {
          error: 'Not Found',
          message: `Original sample bytes not found for ${sampleId}`,
        })
        return
      }
      const bytes = await fs.readFile(samplePath)
      this.sendBuffer(res, 200, bytes, 'application/octet-stream', path.basename(samplePath))
      return
    }

    const analyses = this.dependencies.database.findAnalysesBySample(sampleId).map((analysis) => ({
      id: analysis.id,
      stage: analysis.stage,
      status: analysis.status,
      completed_at: analysis.finished_at,
    }))

    this.sendJson(res, 200, {
      ok: true,
      data: {
        sample_id: sample.id,
        size: sample.size,
        uploaded_at: sample.created_at,
        file_type: sample.file_type,
        analyses,
        download_url: `http://localhost:${this.effectivePort}/api/v1/samples/${encodeURIComponent(sample.id)}?download=true`,
      },
    })
  }

  private async handleArtifactsList(
    req: IncomingMessage,
    res: ServerResponse,
    sampleId: string | null
  ): Promise<void> {
    if (!this.requireApiKey(req, res)) {
      return
    }

    const artifacts = sampleId
      ? this.dependencies.database.findArtifacts(sampleId)
      : this.dependencies.database.findAllArtifacts()

    this.sendJson(res, 200, {
      ok: true,
      data: {
        artifacts: artifacts.map((artifact) => ({
          id: artifact.id,
          sample_id: artifact.sample_id,
          type: artifact.type,
          path: artifact.path,
          sha256: artifact.sha256,
          mime: artifact.mime,
          created_at: artifact.created_at,
          download_url: `http://localhost:${this.effectivePort}/api/v1/artifacts/${encodeURIComponent(artifact.id)}?download=true`,
        })),
        total: artifacts.length,
      },
    })
  }

  private async handleArtifactGet(
    req: IncomingMessage,
    res: ServerResponse,
    artifactId: string,
    download: boolean
  ): Promise<void> {
    if (!this.requireApiKey(req, res)) {
      return
    }

    const artifact = this.dependencies.database.findArtifact(artifactId)
    if (!artifact) {
      this.sendJson(res, 404, {
        error: 'Not Found',
        message: `Artifact not found: ${artifactId}`,
      })
      return
    }

    const artifactPath = await this.resolveArtifactPath(artifact.sample_id, artifact.path)

    if (download) {
      const body = await fs.readFile(artifactPath)
      const filename = path.basename(artifact.path)
      this.sendBuffer(res, 200, body, artifact.mime || 'application/octet-stream', filename)
      return
    }

    const stat = await fs.stat(artifactPath)
    this.sendJson(res, 200, {
      ok: true,
      data: {
        artifact_id: artifact.id,
        sample_id: artifact.sample_id,
        type: artifact.type,
        path: artifact.path,
        sha256: artifact.sha256,
        mime: artifact.mime,
        created_at: artifact.created_at,
        size: stat.size,
        download_url: `http://localhost:${this.effectivePort}/api/v1/artifacts/${encodeURIComponent(artifact.id)}?download=true`,
      },
    })
  }

  private async handleArtifactDelete(
    req: IncomingMessage,
    res: ServerResponse,
    artifactId: string
  ): Promise<void> {
    if (!this.requireApiKey(req, res)) {
      return
    }

    const artifact = this.dependencies.database.findArtifact(artifactId)
    if (!artifact) {
      this.sendJson(res, 404, {
        error: 'Not Found',
        message: `Artifact not found: ${artifactId}`,
      })
      return
    }

    const artifactPath = await this.resolveArtifactPath(artifact.sample_id, artifact.path)
    await fs.rm(artifactPath, { force: true })
    this.dependencies.database.deleteArtifact(artifactId)

    this.sendJson(res, 200, {
      ok: true,
      data: {
        artifact_id: artifactId,
        deleted: true,
      },
    })
  }

  private async handleSessionUpload(
    req: IncomingMessage,
    res: ServerResponse,
    token: string | null
  ): Promise<void> {
    const session = this.validateSession(token)
    if (!token || !session) {
      this.sendJson(res, 404, { error: 'Invalid or expired token' })
      return
    }

    if (session.status === 'expired') {
      this.sendJson(res, 410, { error: 'Token expired' })
      return
    }

    if (session.status === 'registered' && session.sample_id) {
      this.sendJson(res, 200, {
        ok: true,
        data: {
          status: 'registered',
          sample_id: session.sample_id,
          filename: session.filename,
          size: session.size,
        },
      })
      return
    }

    if (session.status !== 'pending') {
      this.sendJson(res, 409, {
        error: 'Upload session is not pending',
        status: session.status,
        sample_id: session.sample_id,
      })
      return
    }

    let stagedPath: string | null = null

    try {
      const body = await this.readBody(req)
      const staged = await this.dependencies.storageManager.stageUpload(
        token,
        body,
        session.filename || 'sample.bin'
      )
      stagedPath = staged.path

      this.dependencies.database.markUploadSessionUploaded(token, {
        staged_path: staged.path,
        size: staged.size,
        filename: staged.filename,
      })

      const finalized = await this.dependencies.finalizationService.finalizeBuffer({
        data: body,
        filename: session.filename || staged.filename,
        source: session.source || 'api_upload',
        auditOperation: 'api.session_upload',
      })

      this.dependencies.database.markUploadSessionRegistered(token, {
        sample_id: finalized.sample_id,
        size: finalized.size,
        sha256: finalized.sha256,
        md5: finalized.md5,
        clearStagedPath: true,
      })

      await this.dependencies.storageManager.deleteStagedUpload(staged.path)

      this.sendJson(res, 201, {
        ok: true,
        data: {
          status: 'registered',
          sample_id: finalized.sample_id,
          filename: staged.filename,
          size: finalized.size,
          file_type: finalized.file_type,
          existed: finalized.existed,
        },
      })
    } catch (error) {
      const normalizedError =
        error instanceof HttpRequestError
          ? error
          : new HttpRequestError(500, 'Upload failed', (error as Error).message)

      this.dependencies.database.markUploadSessionFailed(token, normalizedError.message)

      if (stagedPath) {
        this.dependencies.database.updateUploadSessionByToken(token, {
          staged_path: stagedPath,
        })
      }

      this.sendJson(res, normalizedError.status, {
        error: normalizedError.errorLabel,
        message: normalizedError.message,
      })
    }
  }

  private async handleSessionStatus(res: ServerResponse, token: string | null): Promise<void> {
    const session = this.validateSession(token)
    if (!token || !session) {
      this.sendJson(res, 404, { error: 'Invalid token' })
      return
    }

    this.sendJson(res, 200, {
      ok: true,
      data: {
        token: session.token,
        status: session.status,
        uploaded: session.status === 'uploaded' || session.status === 'registered',
        expires_at: session.expires_at,
        uploaded_at: session.uploaded_at,
        filename: session.filename,
        size: session.size,
        sample_id: session.sample_id,
        error: session.error,
      },
    })
  }
}
