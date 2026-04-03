/**
 * KB MISP event parser — extracts threat intel from MISP JSON events.
 */

import fs from 'fs/promises'

export interface MispKbEntry {
  event_id: string
  event_info: string
  family?: string
  campaign?: string
  tags: string[]
  attribution?: string
  iocs: Array<{
    type: string
    value: string
    comment?: string
  }>
  tlp?: string
}

export async function parseMispEvents(filePath: string): Promise<MispKbEntry[]> {
  const content = await fs.readFile(filePath, 'utf8')
  const parsed = JSON.parse(content)

  // MISP can export as single event or array
  const events: unknown[] = Array.isArray(parsed)
    ? parsed
    : parsed.response
      ? (parsed.response as unknown[])
      : [parsed]

  const entries: MispKbEntry[] = []

  for (const raw of events) {
    if (!raw || typeof raw !== 'object') continue
    const event = (raw as Record<string, unknown>).Event ?? raw
    if (!event || typeof event !== 'object') continue

    const obj = event as Record<string, unknown>
    const entry = extractMispEntry(obj)
    if (entry) entries.push(entry)
  }

  return entries
}

function extractMispEntry(event: Record<string, unknown>): MispKbEntry | null {
  const eventId = String(event.id ?? event.uuid ?? '')
  const eventInfo = String(event.info ?? '')
  if (!eventId && !eventInfo) return null

  const tags: string[] = []
  let family: string | undefined
  let campaign: string | undefined
  let attribution: string | undefined
  let tlp: string | undefined

  // Extract tags
  const tagList = event.Tag as unknown[] | undefined
  if (Array.isArray(tagList)) {
    for (const tag of tagList) {
      if (!tag || typeof tag !== 'object') continue
      const tagObj = tag as Record<string, unknown>
      const tagName = String(tagObj.name ?? '')
      if (!tagName) continue

      tags.push(tagName)

      // Parse well-known tag prefixes
      const lower = tagName.toLowerCase()
      if (lower.startsWith('misp-galaxy:threat-actor=')) {
        attribution = tagName.split('=')[1]?.replace(/"/g, '')
      } else if (lower.startsWith('misp-galaxy:malpedia=') || lower.startsWith('misp-galaxy:malware=')) {
        family = tagName.split('=')[1]?.replace(/"/g, '')
      } else if (lower.startsWith('campaign:')) {
        campaign = tagName.split(':')[1]
      } else if (lower.startsWith('tlp:')) {
        tlp = tagName.split(':')[1]
      }
    }
  }

  // Extract IOCs from attributes
  const iocs: MispKbEntry['iocs'] = []
  const attributes = event.Attribute as unknown[] | undefined
  if (Array.isArray(attributes)) {
    for (const attr of attributes) {
      if (!attr || typeof attr !== 'object') continue
      const attrObj = attr as Record<string, unknown>
      const type = String(attrObj.type ?? '')
      const value = String(attrObj.value ?? '')
      if (type && value) {
        iocs.push({
          type,
          value,
          comment: attrObj.comment ? String(attrObj.comment) : undefined,
        })
      }
    }
  }

  // Also check Object attributes
  const objects = event.Object as unknown[] | undefined
  if (Array.isArray(objects)) {
    for (const obj of objects) {
      if (!obj || typeof obj !== 'object') continue
      const objData = obj as Record<string, unknown>
      const objAttrs = objData.Attribute as unknown[] | undefined
      if (Array.isArray(objAttrs)) {
        for (const attr of objAttrs) {
          if (!attr || typeof attr !== 'object') continue
          const attrObj = attr as Record<string, unknown>
          const type = String(attrObj.type ?? '')
          const value = String(attrObj.value ?? '')
          if (type && value) {
            iocs.push({ type, value })
          }
        }
      }
    }
  }

  return {
    event_id: eventId,
    event_info: eventInfo,
    family,
    campaign,
    tags,
    attribution,
    iocs,
    tlp,
  }
}
