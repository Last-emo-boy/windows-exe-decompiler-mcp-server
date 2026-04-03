/**
 * Format detection utility — detects binary format from magic bytes.
 */

import fs from 'fs'

export type BinaryFormat = 'PE' | 'ELF' | 'MachO' | 'FatMachO' | 'unknown'

const MAGIC_ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46]) // \x7fELF
const MAGIC_PE = Buffer.from([0x4d, 0x5a]) // MZ
const MAGIC_MACHO_32_LE = 0xfeedface
const MAGIC_MACHO_64_LE = 0xfeedfacf
const MAGIC_MACHO_32_BE = 0xcefaedfe
const MAGIC_MACHO_64_BE = 0xcffaedfe
const MAGIC_FAT = 0xcafebabe

export function detectFormat(filePath: string): BinaryFormat {
  let fd: number
  try {
    fd = fs.openSync(filePath, 'r')
  } catch {
    return 'unknown'
  }

  try {
    const buf = Buffer.alloc(4)
    const bytesRead = fs.readSync(fd, buf, 0, 4, 0)
    if (bytesRead < 2) return 'unknown'

    // Check PE (MZ)
    if (buf[0] === MAGIC_PE[0] && buf[1] === MAGIC_PE[1]) return 'PE'

    // Check ELF
    if (bytesRead >= 4 && buf.compare(MAGIC_ELF, 0, 4, 0, 4) === 0) return 'ELF'

    if (bytesRead >= 4) {
      const magic32 = buf.readUInt32BE(0)
      if (magic32 === MAGIC_FAT) return 'FatMachO'
      if (
        magic32 === MAGIC_MACHO_32_LE ||
        magic32 === MAGIC_MACHO_64_LE ||
        magic32 === MAGIC_MACHO_32_BE ||
        magic32 === MAGIC_MACHO_64_BE
      )
        return 'MachO'
    }

    return 'unknown'
  } finally {
    fs.closeSync(fd)
  }
}
