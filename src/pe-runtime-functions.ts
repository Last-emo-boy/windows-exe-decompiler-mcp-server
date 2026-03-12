import fs from 'fs'

export interface PESectionRecord {
  name: string
  virtualAddress: number
  virtualSize: number
  rawSize: number
  rawPointer: number
  characteristics: number
  executable: boolean
}

export interface PEExportRecord {
  rva: number
  name: string
  ordinal: number
  isForwarder: boolean
}

export interface UnwindInfoRecord {
  version: number
  flags: number
  flagNames: string[]
  prologSize: number
  unwindCodeCount: number
  frameRegister: string | null
  frameRegisterId: number
  frameOffset: number
  handlerRva?: number
  chainedRuntimeFunction?: {
    beginRva: number
    endRva: number
    unwindInfoRva: number
  }
}

export interface PERuntimeFunctionEntry {
  beginRva: number
  endRva: number
  size: number
  beginVa: number
  endVa: number
  beginAddress: string
  endAddress: string
  unwindInfoRva: number
  sectionName: string | null
  executableSection: boolean
  confidence: number
  unwind: UnwindInfoRecord | null
}

export interface PdataExtractResult {
  machine: number
  machineName: string
  imageBase: number
  entryPointRva: number
  exceptionDirectoryRva: number
  exceptionDirectorySize: number
  pdataPresent: boolean
  xdataPresent: boolean
  count: number
  sections: PESectionRecord[]
  exports: PEExportRecord[]
  entries: PERuntimeFunctionEntry[]
  warnings: string[]
}

export interface SmartRecoveredFunction {
  address: string
  va: number
  rva: number
  size: number
  name: string
  nameSource: 'entry_point' | 'export' | 'synthetic_sub'
  confidence: number
  source: 'pdata_runtime_function' | 'entry_point_only'
  sectionName: string | null
  executableSection: boolean
  isEntryPoint: boolean
  isExported: boolean
  exportName?: string
  unwind?: UnwindInfoRecord | null
  evidence: string[]
}

export interface SmartRecoverResult {
  machine: number
  machineName: string
  imageBase: number
  entryPointRva: number
  strategy: string[]
  count: number
  functions: SmartRecoveredFunction[]
  warnings: string[]
}

const IMAGE_FILE_MACHINE_NAMES: Record<number, string> = {
  0x014c: 'IMAGE_FILE_MACHINE_I386',
  0x0200: 'IMAGE_FILE_MACHINE_IA64',
  0x8664: 'IMAGE_FILE_MACHINE_AMD64',
  0x01c4: 'IMAGE_FILE_MACHINE_ARMNT',
  0xaa64: 'IMAGE_FILE_MACHINE_ARM64',
}

const UNWIND_FLAG_NAMES: Array<[number, string]> = [
  [0x1, 'EHANDLER'],
  [0x2, 'UHANDLER'],
  [0x4, 'CHAININFO'],
]

const X64_REGISTER_NAMES = [
  null,
  'RCX',
  'RDX',
  'RBX',
  'RSP',
  'RBP',
  'RSI',
  'RDI',
  'R8',
  'R9',
  'R10',
  'R11',
  'R12',
  'R13',
  'R14',
  'R15',
] as const

interface PEContext {
  buffer: Buffer
  filePath: string
  machine: number
  machineName: string
  imageBase: number
  entryPointRva: number
  exceptionDirectoryRva: number
  exceptionDirectorySize: number
  sections: PESectionRecord[]
}

function readUInt64AsNumber(buffer: Buffer, offset: number): number {
  const low = buffer.readUInt32LE(offset)
  const high = buffer.readUInt32LE(offset + 4)
  return high * 0x1_0000_0000 + low
}

function formatHex(value: number): string {
  const width = value > 0xffffffff ? 16 : 8
  return `0x${value.toString(16).padStart(width, '0')}`
}

function readNullTerminatedAscii(buffer: Buffer, offset: number): string {
  let end = offset
  while (end < buffer.length && buffer[end] !== 0) {
    end += 1
  }
  return buffer.toString('ascii', offset, end)
}

function getSectionForRva(sections: PESectionRecord[], rva: number): PESectionRecord | undefined {
  return sections.find((section) => {
    const maxSize = Math.max(section.virtualSize, section.rawSize)
    return rva >= section.virtualAddress && rva < section.virtualAddress + maxSize
  })
}

function rvaToOffset(buffer: Buffer, sections: PESectionRecord[], rva: number): number | undefined {
  if (rva < 0 || rva >= buffer.length) {
    const section = getSectionForRva(sections, rva)
    if (!section) {
      return undefined
    }
    const delta = rva - section.virtualAddress
    if (delta < 0 || delta >= section.rawSize) {
      return undefined
    }
    return section.rawPointer + delta
  }

  const section = getSectionForRva(sections, rva)
  if (!section) {
    return rva
  }
  const delta = rva - section.virtualAddress
  if (delta < 0 || delta >= section.rawSize) {
    return undefined
  }
  return section.rawPointer + delta
}

function parseSectionHeaders(
  buffer: Buffer,
  sectionTableOffset: number,
  numberOfSections: number
): PESectionRecord[] {
  const sections: PESectionRecord[] = []
  for (let index = 0; index < numberOfSections; index += 1) {
    const offset = sectionTableOffset + index * 40
    if (offset + 40 > buffer.length) {
      break
    }
    const rawName = buffer.toString('ascii', offset, offset + 8)
    const name = rawName.replace(/\0+$/g, '')
    const virtualSize = buffer.readUInt32LE(offset + 8)
    const virtualAddress = buffer.readUInt32LE(offset + 12)
    const rawSize = buffer.readUInt32LE(offset + 16)
    const rawPointer = buffer.readUInt32LE(offset + 20)
    const characteristics = buffer.readUInt32LE(offset + 36)
    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawSize,
      rawPointer,
      characteristics,
      executable: (characteristics & 0x20000000) !== 0,
    })
  }
  return sections
}

function parsePEContext(filePath: string): PEContext {
  const buffer = fs.readFileSync(filePath)
  if (buffer.length < 0x100) {
    throw new Error('File is too small to be a valid PE image.')
  }
  if (buffer.toString('ascii', 0, 2) !== 'MZ') {
    throw new Error('File does not start with an MZ DOS header.')
  }

  const peOffset = buffer.readUInt32LE(0x3c)
  if (peOffset + 4 + 20 > buffer.length) {
    throw new Error('PE header offset points outside the file.')
  }
  if (buffer.toString('ascii', peOffset, peOffset + 4) !== 'PE\u0000\u0000') {
    throw new Error('PE signature was not found at e_lfanew.')
  }

  const fileHeaderOffset = peOffset + 4
  const machine = buffer.readUInt16LE(fileHeaderOffset)
  const numberOfSections = buffer.readUInt16LE(fileHeaderOffset + 2)
  const sizeOfOptionalHeader = buffer.readUInt16LE(fileHeaderOffset + 16)
  const optionalHeaderOffset = fileHeaderOffset + 20
  const optionalMagic = buffer.readUInt16LE(optionalHeaderOffset)
  const isPe32Plus = optionalMagic === 0x20b
  const isPe32 = optionalMagic === 0x10b
  if (!isPe32Plus && !isPe32) {
    throw new Error(`Unsupported PE optional header magic: 0x${optionalMagic.toString(16)}`)
  }

  const entryPointRva = buffer.readUInt32LE(optionalHeaderOffset + 16)
  const imageBase = isPe32Plus
    ? readUInt64AsNumber(buffer, optionalHeaderOffset + 24)
    : buffer.readUInt32LE(optionalHeaderOffset + 28)
  const dataDirectoryStart = optionalHeaderOffset + (isPe32Plus ? 112 : 96)
  const numberOfRvaAndSizes = buffer.readUInt32LE(optionalHeaderOffset + (isPe32Plus ? 108 : 92))
  let exceptionDirectoryRva = 0
  let exceptionDirectorySize = 0
  if (numberOfRvaAndSizes > 3 && dataDirectoryStart + 32 <= buffer.length) {
    exceptionDirectoryRva = buffer.readUInt32LE(dataDirectoryStart + 8 * 3)
    exceptionDirectorySize = buffer.readUInt32LE(dataDirectoryStart + 8 * 3 + 4)
  }

  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader
  const sections = parseSectionHeaders(buffer, sectionTableOffset, numberOfSections)

  return {
    buffer,
    filePath,
    machine,
    machineName: IMAGE_FILE_MACHINE_NAMES[machine] || `UNKNOWN_0x${machine.toString(16)}`,
    imageBase,
    entryPointRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    sections,
  }
}

function parseExportTable(context: PEContext): PEExportRecord[] {
  const { buffer, sections } = context
  const peOffset = buffer.readUInt32LE(0x3c)
  const fileHeaderOffset = peOffset + 4
  const optionalHeaderOffset = fileHeaderOffset + 20
  const optionalMagic = buffer.readUInt16LE(optionalHeaderOffset)
  const isPe32Plus = optionalMagic === 0x20b
  const dataDirectoryStart = optionalHeaderOffset + (isPe32Plus ? 112 : 96)
  const numberOfRvaAndSizes = buffer.readUInt32LE(optionalHeaderOffset + (isPe32Plus ? 108 : 92))
  if (numberOfRvaAndSizes < 1) {
    return []
  }

  const exportRva = buffer.readUInt32LE(dataDirectoryStart)
  const exportSize = buffer.readUInt32LE(dataDirectoryStart + 4)
  if (!exportRva || !exportSize) {
    return []
  }

  const exportOffset = rvaToOffset(buffer, sections, exportRva)
  if (exportOffset === undefined || exportOffset + 40 > buffer.length) {
    return []
  }

  const ordinalBase = buffer.readUInt32LE(exportOffset + 16)
  const numberOfFunctions = buffer.readUInt32LE(exportOffset + 20)
  const numberOfNames = buffer.readUInt32LE(exportOffset + 24)
  const addressOfFunctionsRva = buffer.readUInt32LE(exportOffset + 28)
  const addressOfNamesRva = buffer.readUInt32LE(exportOffset + 32)
  const addressOfNameOrdinalsRva = buffer.readUInt32LE(exportOffset + 36)
  const addressOfFunctionsOffset = rvaToOffset(buffer, sections, addressOfFunctionsRva)
  const addressOfNamesOffset = rvaToOffset(buffer, sections, addressOfNamesRva)
  const addressOfNameOrdinalsOffset = rvaToOffset(buffer, sections, addressOfNameOrdinalsRva)
  if (
    addressOfFunctionsOffset === undefined ||
    addressOfNamesOffset === undefined ||
    addressOfNameOrdinalsOffset === undefined
  ) {
    return []
  }

  const records: PEExportRecord[] = []
  for (let index = 0; index < numberOfNames; index += 1) {
    const nameRva = buffer.readUInt32LE(addressOfNamesOffset + index * 4)
    const nameOffset = rvaToOffset(buffer, sections, nameRva)
    const ordinalIndex = buffer.readUInt16LE(addressOfNameOrdinalsOffset + index * 2)
    if (nameOffset === undefined || ordinalIndex >= numberOfFunctions) {
      continue
    }
    const functionRva = buffer.readUInt32LE(addressOfFunctionsOffset + ordinalIndex * 4)
    const name = readNullTerminatedAscii(buffer, nameOffset)
    const isForwarder = functionRva >= exportRva && functionRva < exportRva + exportSize
    records.push({
      rva: functionRva,
      name,
      ordinal: ordinalBase + ordinalIndex,
      isForwarder,
    })
  }
  return records
}

function parseUnwindInfo(context: PEContext, unwindInfoRva: number): UnwindInfoRecord | null {
  const { buffer, sections } = context
  const offset = rvaToOffset(buffer, sections, unwindInfoRva)
  if (offset === undefined || offset + 4 > buffer.length) {
    return null
  }

  const versionAndFlags = buffer.readUInt8(offset)
  const version = versionAndFlags & 0x7
  const flags = versionAndFlags >> 3
  const prologSize = buffer.readUInt8(offset + 1)
  const unwindCodeCount = buffer.readUInt8(offset + 2)
  const frameRegisterAndOffset = buffer.readUInt8(offset + 3)
  const frameRegisterId = frameRegisterAndOffset & 0x0f
  const frameOffset = frameRegisterAndOffset >> 4
  const flagNames = UNWIND_FLAG_NAMES
    .filter(([flag]) => (flags & flag) !== 0)
    .map(([, name]) => name)

  let trailingOffset = offset + 4 + unwindCodeCount * 2
  if (trailingOffset % 4 !== 0) {
    trailingOffset += 4 - (trailingOffset % 4)
  }

  const info: UnwindInfoRecord = {
    version,
    flags,
    flagNames,
    prologSize,
    unwindCodeCount,
    frameRegister: X64_REGISTER_NAMES[frameRegisterId] || null,
    frameRegisterId,
    frameOffset,
  }

  if ((flags & 0x4) !== 0 && trailingOffset + 12 <= buffer.length) {
    info.chainedRuntimeFunction = {
      beginRva: buffer.readUInt32LE(trailingOffset),
      endRva: buffer.readUInt32LE(trailingOffset + 4),
      unwindInfoRva: buffer.readUInt32LE(trailingOffset + 8),
    }
  } else if ((flags & 0x3) !== 0 && trailingOffset + 4 <= buffer.length) {
    info.handlerRva = buffer.readUInt32LE(trailingOffset)
  }

  return info
}

export function extractPdataFromPE(filePath: string): PdataExtractResult {
  const context = parsePEContext(filePath)
  const { buffer, sections, imageBase, entryPointRva } = context
  const warnings: string[] = []
  const exports = parseExportTable(context)
  let exceptionDirectoryRva = context.exceptionDirectoryRva
  let exceptionDirectorySize = context.exceptionDirectorySize

  if (!exceptionDirectoryRva || !exceptionDirectorySize) {
    const pdataSection = sections.find((section) => section.name.toLowerCase() === '.pdata')
    if (pdataSection) {
      exceptionDirectoryRva = pdataSection.virtualAddress
      exceptionDirectorySize = Math.min(pdataSection.virtualSize || pdataSection.rawSize, pdataSection.rawSize)
      warnings.push('Exception directory metadata was empty; fell back to the .pdata section bounds.')
    }
  }

  const entries: PERuntimeFunctionEntry[] = []
  if (!exceptionDirectoryRva || !exceptionDirectorySize) {
    return {
      machine: context.machine,
      machineName: context.machineName,
      imageBase,
      entryPointRva,
      exceptionDirectoryRva: 0,
      exceptionDirectorySize: 0,
      pdataPresent: false,
      xdataPresent: sections.some((section) => section.name.toLowerCase() === '.xdata'),
      count: 0,
      sections,
      exports,
      entries,
      warnings: ['PE image has no exception directory / .pdata section to parse.'],
    }
  }

  const exceptionDirectoryOffset = rvaToOffset(buffer, sections, exceptionDirectoryRva)
  if (exceptionDirectoryOffset === undefined) {
    throw new Error('Exception directory RVA could not be mapped to a file offset.')
  }

  const availableBytes = Math.max(0, Math.min(exceptionDirectorySize, buffer.length - exceptionDirectoryOffset))
  if (availableBytes % 12 !== 0) {
    warnings.push(`Exception directory size (${availableBytes}) is not a multiple of 12 bytes.`)
  }

  for (let offset = 0; offset + 12 <= availableBytes; offset += 12) {
    const beginRva = buffer.readUInt32LE(exceptionDirectoryOffset + offset)
    const endRva = buffer.readUInt32LE(exceptionDirectoryOffset + offset + 4)
    const unwindInfoRva = buffer.readUInt32LE(exceptionDirectoryOffset + offset + 8)

    if (beginRva === 0 && endRva === 0 && unwindInfoRva === 0) {
      continue
    }
    if (!beginRva || !endRva || endRva <= beginRva) {
      warnings.push(`Skipped malformed RUNTIME_FUNCTION entry at directory offset +0x${offset.toString(16)}.`)
      continue
    }

    const section = getSectionForRva(sections, beginRva)
    const unwind = unwindInfoRva ? parseUnwindInfo(context, unwindInfoRva) : null
    let confidence = 0.68
    if (section?.executable) {
      confidence += 0.12
    }
    if (unwind) {
      confidence += 0.12
      if (unwind.handlerRva || unwind.chainedRuntimeFunction) {
        confidence += 0.05
      }
    }
    if (beginRva === entryPointRva) {
      confidence += 0.03
    }
    confidence = Math.min(confidence, 0.96)

    entries.push({
      beginRva,
      endRva,
      size: endRva - beginRva,
      beginVa: imageBase + beginRva,
      endVa: imageBase + endRva,
      beginAddress: formatHex(imageBase + beginRva),
      endAddress: formatHex(imageBase + endRva),
      unwindInfoRva,
      sectionName: section?.name || null,
      executableSection: section?.executable || false,
      confidence,
      unwind,
    })
  }

  entries.sort((left, right) => left.beginRva - right.beginRva)

  return {
    machine: context.machine,
    machineName: context.machineName,
    imageBase,
    entryPointRva,
    exceptionDirectoryRva,
    exceptionDirectorySize,
    pdataPresent: true,
    xdataPresent: sections.some((section) => section.name.toLowerCase() === '.xdata'),
    count: entries.length,
    sections,
    exports,
    entries,
    warnings,
  }
}

export function smartRecoverFunctionsFromPE(filePath: string): SmartRecoverResult {
  const pdata = extractPdataFromPE(filePath)
  const exportByRva = new Map<number, PEExportRecord>()
  for (const record of pdata.exports) {
    if (!record.isForwarder && !exportByRva.has(record.rva)) {
      exportByRva.set(record.rva, record)
    }
  }

  const functions: SmartRecoveredFunction[] = pdata.entries.map((entry) => {
    const exportMatch = exportByRva.get(entry.beginRva)
    const isEntryPoint = entry.beginRva === pdata.entryPointRva
    let name = `sub_${entry.beginRva.toString(16).padStart(8, '0')}`
    let nameSource: SmartRecoveredFunction['nameSource'] = 'synthetic_sub'
    if (exportMatch?.name) {
      name = exportMatch.name
      nameSource = 'export'
    } else if (isEntryPoint) {
      name = 'entry_point'
      nameSource = 'entry_point'
    }

    const evidence = [
      'Recovered from PE exception directory (.pdata) runtime function entry.',
      `Size=${entry.size} bytes`,
    ]
    if (entry.sectionName) {
      evidence.push(`Section=${entry.sectionName}`)
    }
    if (entry.unwind) {
      evidence.push(`Unwind flags=${entry.unwind.flagNames.join('|') || 'none'}`)
    }
    if (exportMatch?.name) {
      evidence.push(`Matched export ${exportMatch.name}`)
    }
    if (isEntryPoint) {
      evidence.push('Matches PE entry point RVA')
    }

    return {
      address: entry.beginAddress,
      va: entry.beginVa,
      rva: entry.beginRva,
      size: entry.size,
      name,
      nameSource,
      confidence: entry.confidence,
      source: 'pdata_runtime_function',
      sectionName: entry.sectionName,
      executableSection: entry.executableSection,
      isEntryPoint,
      isExported: Boolean(exportMatch),
      exportName: exportMatch?.name,
      unwind: entry.unwind,
      evidence,
    }
  })

  const hasEntrypoint = functions.some((item) => item.isEntryPoint)
  if (!hasEntrypoint && pdata.entryPointRva > 0) {
    const section = getSectionForRva(pdata.sections, pdata.entryPointRva)
    functions.unshift({
      address: formatHex(pdata.imageBase + pdata.entryPointRva),
      va: pdata.imageBase + pdata.entryPointRva,
      rva: pdata.entryPointRva,
      size: 0,
      name: 'entry_point',
      nameSource: 'entry_point',
      confidence: 0.42,
      source: 'entry_point_only',
      sectionName: section?.name || null,
      executableSection: section?.executable || false,
      isEntryPoint: true,
      isExported: false,
      evidence: ['Recovered directly from PE AddressOfEntryPoint because no .pdata entry matched it.'],
      unwind: null,
    })
  }

  const deduped = new Map<number, SmartRecoveredFunction>()
  for (const item of functions) {
    const existing = deduped.get(item.rva)
    if (!existing || item.confidence > existing.confidence) {
      deduped.set(item.rva, item)
    }
  }

  return {
    machine: pdata.machine,
    machineName: pdata.machineName,
    imageBase: pdata.imageBase,
    entryPointRva: pdata.entryPointRva,
    strategy: dedupeStrings([
      pdata.count > 0 ? 'pdata_runtime_functions' : '',
      pdata.exports.length > 0 ? 'export_surface' : '',
      pdata.entryPointRva > 0 ? 'entry_point' : '',
    ]),
    count: deduped.size,
    functions: Array.from(deduped.values()).sort((left, right) => left.rva - right.rva),
    warnings: pdata.warnings,
  }
}

function dedupeStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((item) => item.length > 0)))
}
