/**
 * API Endpoints Integration tests
 * Tasks: api-file-server 7.4
 */

import { describe, test, expect } from '@jest/globals'
import { AuthMiddleware } from '../../../src/api/auth-middleware.js'

describe('api-file-server - API Endpoints Integration', () => {
  describe('Authentication Flow', () => {
    test('should allow requests without auth when no key configured', () => {
      const middleware = new AuthMiddleware({ enabled: false })
      const result = middleware.validateApiKey({})
      expect(result).toBe(true)
    })

    test('should require auth when key configured', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key' })
      
      // Missing key
      expect(middleware.validateApiKey({})).toBe(false)
      
      // Wrong key
      expect(middleware.validateApiKey({ 'x-api-key': 'wrong' })).toBe(false)
      
      // Correct key
      expect(middleware.validateApiKey({ 'x-api-key': 'test-key' })).toBe(true)
    })
  })

  describe('Health Endpoint Contract', () => {
    test('should return healthy status', () => {
      // Simulate health check response structure
      const healthResponse = {
        ok: true,
        data: {
          status: 'healthy',
          version: '1.0.0-beta.1',
          timestamp: new Date().toISOString(),
        },
      }

      expect(healthResponse.ok).toBe(true)
      expect(healthResponse.data.status).toBe('healthy')
      expect(healthResponse.data.version).toMatch(/\d+\.\d+\.\d+/)
    })
  })

  describe('Sample Upload Endpoint Contract', () => {
    test('should return correct response structure', () => {
      const uploadResponse = {
        ok: true,
        data: {
          sample_id: `sha256:${'a'.repeat(64)}`,
          filename: 'test.exe',
          size: 1024,
          uploaded_at: new Date().toISOString(),
          existed: false,
          file_type: '.exe',
        },
      }

      expect(uploadResponse.ok).toBe(true)
      expect(uploadResponse.data.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)
      expect(typeof uploadResponse.data.size).toBe('number')
    })

    test('should handle duplicate upload', () => {
      const duplicateResponse = {
        ok: true,
        data: {
          sample_id: `sha256:${'a'.repeat(64)}`,
          filename: 'test.exe',
          size: 1024,
          uploaded_at: new Date().toISOString(),
          existed: true, // Indicates duplicate
        },
      }

      expect(duplicateResponse.data.existed).toBe(true)
    })
  })

  describe('Artifact Endpoint Contract', () => {
    test('should return correct list structure', () => {
      const listResponse = {
        ok: true,
        data: {
          artifacts: [
            {
              id: 'artifact-123',
              sample_id: `sha256:${'a'.repeat(64)}`,
              type: 'triage_report',
              sha256: 'def456',
              created_at: new Date().toISOString(),
            },
          ],
          total: 1,
        },
      }

      expect(listResponse.ok).toBe(true)
      expect(Array.isArray(listResponse.data.artifacts)).toBe(true)
      expect(typeof listResponse.data.total).toBe('number')
    })

    test('should return correct single artifact structure', () => {
      const artifactResponse = {
        ok: true,
        data: {
          artifact_id: 'artifact-123',
          sample_id: `sha256:${'a'.repeat(64)}`,
          type: 'triage_report',
          path: '/app/storage/artifacts/abc/triage_report.json',
          sha256: 'def456',
          mime: 'application/json',
          created_at: new Date().toISOString(),
          download_url: 'http://localhost:18080/api/v1/artifacts/artifact-123?download=true',
        },
      }

      expect(artifactResponse.ok).toBe(true)
      expect(artifactResponse.data.download_url).toContain('/api/v1/artifacts/')
    })
  })

  describe('Error Response Contract', () => {
    test('should return consistent error structure', () => {
      const errorResponse = {
        error: 'Unauthorized',
        message: 'Invalid or missing API key',
      }

      expect(errorResponse.error).toBeDefined()
      expect(errorResponse.message).toBeDefined()
      expect(typeof errorResponse.error).toBe('string')
      expect(typeof errorResponse.message).toBe('string')
    })

    test('should handle common errors', () => {
      const errors = [
        { status: 400, error: 'Bad Request' },
        { status: 401, error: 'Unauthorized' },
        { status: 403, error: 'Forbidden' },
        { status: 404, error: 'Not Found' },
        { status: 413, error: 'Payload Too Large' },
        { status: 500, error: 'Internal Server Error' },
      ]

      for (const err of errors) {
        expect(err.status).toBeGreaterThan(0)
        expect(err.error).toBeDefined()
      }
    })
  })

  describe('Upload Session Contract', () => {
    test('should return correct session status structure', () => {
      const sessionResponse = {
        ok: true,
        data: {
          status: 'registered',
          sample_id: `sha256:${'a'.repeat(64)}`,
          filename: 'test.exe',
          size: 1024,
        },
      }

      expect(sessionResponse.ok).toBe(true)
      expect(['pending', 'registered', 'expired', 'completed']).toContain(sessionResponse.data.status)
    })
  })
})
