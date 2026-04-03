/**
 * Unit tests for ELF/Mach-O cross-platform support
 */

import { detectFileType } from '../../src/sample-finalization.js'

describe('detectFileType', () => {
  it('detects PE (MZ header)', () => {
    const buf = Buffer.alloc(64)
    buf[0] = 0x4d // M
    buf[1] = 0x5a // Z
    expect(detectFileType(buf)).toBe('PE')
  })

  it('detects ELF', () => {
    const buf = Buffer.alloc(64)
    buf[0] = 0x7f
    buf[1] = 0x45 // E
    buf[2] = 0x4c // L
    buf[3] = 0x46 // F
    expect(detectFileType(buf)).toBe('ELF')
  })

  it('detects Mach-O 32-bit', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xfeedface, 0)
    expect(detectFileType(buf)).toBe('Mach-O')
  })

  it('detects Mach-O 64-bit', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xfeedfacf, 0)
    expect(detectFileType(buf)).toBe('Mach-O')
  })

  it('detects Mach-O 32-bit reverse endian', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xcefaedfe, 0)
    expect(detectFileType(buf)).toBe('Mach-O')
  })

  it('detects Mach-O 64-bit reverse endian', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xcffaedfe, 0)
    expect(detectFileType(buf)).toBe('Mach-O')
  })

  it('detects Mach-O fat binary', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xcafebabe, 0)
    expect(detectFileType(buf)).toBe('Mach-O-Fat')
  })

  it('detects Mach-O fat binary reverse endian', () => {
    const buf = Buffer.alloc(64)
    buf.writeUInt32BE(0xbebafeca, 0)
    expect(detectFileType(buf)).toBe('Mach-O-Fat')
  })

  it('returns unknown for unrecognized format', () => {
    const buf = Buffer.alloc(64, 0x00)
    expect(detectFileType(buf)).toBe('unknown')
  })

  it('returns unknown for too-short buffer', () => {
    const buf = Buffer.alloc(1)
    expect(detectFileType(buf)).toBe('unknown')
  })

  it('PE detection takes priority over others when only MZ present', () => {
    const buf = Buffer.alloc(64, 0x00)
    buf[0] = 0x4d
    buf[1] = 0x5a
    expect(detectFileType(buf)).toBe('PE')
  })
})

describe('elf-structure-analyze', () => {
  it('module exports tool definition and handler factory', async () => {
    const mod = await import('../../src/tools/elf-structure-analyze.js')
    expect(mod.elfStructureAnalyzeToolDefinition).toBeDefined()
    expect(mod.elfStructureAnalyzeToolDefinition.name).toBe('elf.structure.analyze')
    expect(typeof mod.createElfStructureAnalyzeHandler).toBe('function')
  })
})

describe('macho-structure-analyze', () => {
  it('module exports tool definition and handler factory', async () => {
    const mod = await import('../../src/tools/macho-structure-analyze.js')
    expect(mod.machoStructureAnalyzeToolDefinition).toBeDefined()
    expect(mod.machoStructureAnalyzeToolDefinition.name).toBe('macho.structure.analyze')
    expect(typeof mod.createMachoStructureAnalyzeHandler).toBe('function')
  })
})

describe('elf-imports-extract', () => {
  it('module exports tool definition and handler factory', async () => {
    const mod = await import('../../src/tools/elf-imports-extract.js')
    expect(mod.elfImportsExtractToolDefinition).toBeDefined()
    expect(mod.elfImportsExtractToolDefinition.name).toBe('elf.imports.extract')
    expect(typeof mod.createElfImportsExtractHandler).toBe('function')
  })
})

describe('elf-exports-extract', () => {
  it('module exports tool definition and handler factory', async () => {
    const mod = await import('../../src/tools/elf-exports-extract.js')
    expect(mod.elfExportsExtractToolDefinition).toBeDefined()
    expect(mod.elfExportsExtractToolDefinition.name).toBe('elf.exports.extract')
    expect(typeof mod.createElfExportsExtractHandler).toBe('function')
  })
})
