/**
 * Unit tests for static.worker.client utility
 */

import { describe, test, expect } from '@jest/globals'
import { buildStaticWorkerRequest, callStaticWorker } from '../../src/tools/static-worker-client.js'

describe('static.worker.client utility', () => {
  describe('buildStaticWorkerRequest', () => {
    test('should be a function', () => {
      expect(typeof buildStaticWorkerRequest).toBe('function')
    })
  })

  describe('callStaticWorker', () => {
    test('should be a function', () => {
      expect(typeof callStaticWorker).toBe('function')
    })
  })
})
