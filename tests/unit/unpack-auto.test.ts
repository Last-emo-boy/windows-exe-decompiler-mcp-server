/**
 * Unit tests for auto-unpack-pipeline
 */

import {
  selectUnpackStrategy,
  type PackerDetectionResult,
} from '../../src/unpack-strategy.js'

describe('unpack-strategy', () => {
  describe('selectUnpackStrategy', () => {
    it('returns null for non-packed sample', () => {
      const result = selectUnpackStrategy({
        packed: false,
        confidence: 0,
        packer_names: [],
      })
      expect(result).toBeNull()
    })

    it('selects upx_cli for UPX packed sample', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.9,
        packer_names: ['UPX'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('upx_cli')
      expect(result!.packer_name).toBe('UPX')
    })

    it('selects upx_cli even at low confidence for UPX', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.3,
        packer_names: ['upx'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('upx_cli')
    })

    it('rejects UPX below min confidence', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.1,
        packer_names: ['UPX'],
      })
      // Below 0.3 threshold but packed=true,
      // will fall through to high_entropy fallback if confidence < 0.5
      expect(result).toBeNull()
    })

    it('selects speakeasy_dump for Themida', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.7,
        packer_names: ['Themida'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('speakeasy_dump')
    })

    it('selects speakeasy_dump for VMProtect', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.6,
        packer_names: ['VMProtect'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('speakeasy_dump')
    })

    it('selects speakeasy_dump for unknown packer at high confidence', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.8,
        packer_names: ['unknown'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('speakeasy_dump')
    })

    it('falls back to speakeasy for high-entropy unknown', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.6,
        packer_names: [],
        high_entropy: true,
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('speakeasy_dump')
    })

    it('returns null for low-confidence unknown packer without high entropy', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.2,
        packer_names: [],
      })
      expect(result).toBeNull()
    })

    it('picks first matching strategy from multiple packer names', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.9,
        packer_names: ['UPX', 'Themida'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('upx_cli') // UPX matched first
    })

    it('skips non-matching packer and matches second', () => {
      const result = selectUnpackStrategy({
        packed: true,
        confidence: 0.7,
        packer_names: ['CustomPacker123', 'ASPack'],
      })
      expect(result).not.toBeNull()
      expect(result!.backend).toBe('speakeasy_dump')
      expect(result!.packer_name).toBe('ASPack')
    })
  })
})
