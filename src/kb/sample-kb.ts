/**
 * Sample Knowledge Base API
 * Tasks: collaborative-knowledge-base 5.1-5.5
 */

import crypto from 'crypto'
import type { DatabaseManager } from '../database.js'

export interface LinkSampleToThreatData {
  sampleId: string
  family?: string
  campaign?: string
  tags?: string[]
  attribution?: string
  userId?: string
}

export async function linkSampleToThreat(db: DatabaseManager, data: LinkSampleToThreatData): Promise<string> {
  const id = crypto.randomUUID()
  const now = new Date().toISOString()
  
  db.runSql(`
    INSERT INTO sample_kb (id, sample_id, threat_intel_family, threat_intel_campaign, threat_intel_tags_json, threat_intel_attribution, created_at, updated_at, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [id, data.sampleId, data.family || null, data.campaign || null, JSON.stringify(data.tags || []), data.attribution || null, now, now, data.userId || null])
  
  return id
}

export function getSampleThreatLinks(db: DatabaseManager, sampleId: string): { family?: string; campaign?: string; tags: string[]; attribution?: string } | null {
  const rows = db.querySql<any>('SELECT * FROM sample_kb WHERE sample_id = ?', [sampleId])
  const row = rows[0]
  if (!row) return null
  
  return {
    family: row.threat_intel_family,
    campaign: row.threat_intel_campaign,
    tags: JSON.parse(row.threat_intel_tags_json),
    attribution: row.threat_intel_attribution,
  }
}

export function searchSamplesByFamily(db: DatabaseManager, family: string, limit = 20): Array<{ sample_id: string; family: string; campaign?: string; tags: string[]; attribution?: string }> {
  const rows = db.querySql<any>('SELECT sample_id, threat_intel_family, threat_intel_campaign, threat_intel_tags_json, threat_intel_attribution FROM sample_kb WHERE threat_intel_family LIKE ? ORDER BY updated_at DESC LIMIT ?', [`%${family}%`, limit])
  return rows.map(row => ({ sample_id: row.sample_id, family: row.threat_intel_family, campaign: row.threat_intel_campaign || undefined, tags: JSON.parse(row.threat_intel_tags_json), attribution: row.threat_intel_attribution || undefined }))
}

export function getThreatIntelStats(db: DatabaseManager): { totalSamples: number; families: Array<{ name: string; count: number }>; campaigns: Array<{ name: string; count: number }>; topTags: Array<{ tag: string; count: number }> } {
  const totalRow = db.queryOneSql<{ count: number }>('SELECT COUNT(*) as count FROM sample_kb')
  const families = db.querySql<any>('SELECT threat_intel_family as family, COUNT(*) as count FROM sample_kb WHERE threat_intel_family IS NOT NULL GROUP BY threat_intel_family ORDER BY count DESC LIMIT 10')
  const campaigns = db.querySql<any>('SELECT threat_intel_campaign as campaign, COUNT(*) as count FROM sample_kb WHERE threat_intel_campaign IS NOT NULL GROUP BY threat_intel_campaign ORDER BY count DESC LIMIT 10')
  
  const tagRows = db.querySql<any>('SELECT threat_intel_tags_json FROM sample_kb')
  const tagCounts = new Map<string, number>()
  for (const row of tagRows) {
    const tags = JSON.parse(row.threat_intel_tags_json) as string[]
    for (const tag of tags) tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1)
  }
  const topTags = Array.from(tagCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([tag, count]) => ({ tag, count }))
  
  return { totalSamples: totalRow?.count || 0, families: families.map(f => ({ name: f.family, count: f.count })), campaigns: campaigns.map(c => ({ name: c.campaign, count: c.count })), topTags }
}
