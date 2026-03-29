/**
 * API Auth Middleware tests
 * Tasks: api-file-server 7.1
 */

import { describe, test, expect } from '@jest/globals'
import { AuthMiddleware } from '../../../src/api/auth-middleware.js'

describe('api-file-server - Auth Middleware', () => {
  describe('validateApiKey', () => {
    test('should return true when no API key is configured', () => {
      const middleware = new AuthMiddleware({ enabled: false })
      const result = middleware.validateApiKey({})
      expect(result).toBe(true)
    })

    test('should return true when API key matches', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key-123' })
      const headers = { 'x-api-key': 'test-key-123' }
      const result = middleware.validateApiKey(headers)
      expect(result).toBe(true)
    })

    test('should return false when API key does not match', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key-123' })
      const headers = { 'x-api-key': 'wrong-key' }
      const result = middleware.validateApiKey(headers)
      expect(result).toBe(false)
    })

    test('should return false when API key is missing', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key-123' })
      const headers = {}
      const result = middleware.validateApiKey(headers)
      expect(result).toBe(false)
    })
  })

  describe('getAuthError', () => {
    test('should return 403 when key was provided but invalid', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key' })
      middleware.validateApiKey({ 'x-api-key': 'wrong' })
      const error = middleware.getAuthError(true)
      expect(error.status).toBe(403)
      expect(JSON.parse(error.body).error).toBe('Forbidden')
    })

    test('should return 401 when key was missing', () => {
      const middleware = new AuthMiddleware({ enabled: true, apiKey: 'test-key' })
      middleware.validateApiKey({})
      const error = middleware.getAuthError(false)
      expect(error.status).toBe(401)
      expect(JSON.parse(error.body).error).toBe('Unauthorized')
    })
  })
})
