/**
 * Team Knowledge Base - Multi-user Support
 * Tasks: collaborative-knowledge-base 6.1-6.5
 */

import type { DatabaseManager } from '../database.js'
import { searchFunctions, type SearchFunctionsQuery } from './search-kb.js'
import { contributeFunction } from './function-kb.js'

export interface TeamKbConfig { teamId: string; visibility: 'private' | 'shared'; defaultAccessLevel: 'read' | 'write' | 'admin' }

export function initializeTeamKb(db: DatabaseManager): void {
  db.runSql(`CREATE TABLE IF NOT EXISTS team_kb_config (team_id TEXT PRIMARY KEY, visibility TEXT NOT NULL DEFAULT 'private', default_access_level TEXT NOT NULL DEFAULT 'read', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`)
  db.runSql(`CREATE TABLE IF NOT EXISTS team_kb_members (user_id TEXT NOT NULL, team_id TEXT NOT NULL, access_level TEXT NOT NULL, joined_at TEXT NOT NULL, PRIMARY KEY (user_id, team_id))`)
  db.runSql(`CREATE INDEX IF NOT EXISTS idx_team_kb_members_team ON team_kb_members(team_id)`)
  try { db.runSql(`ALTER TABLE function_kb ADD COLUMN team_id TEXT`) } catch (e) { /* Column may already exist */ }
}

export async function createTeamKb(db: DatabaseManager, config: TeamKbConfig, creatorId: string): Promise<void> {
  const now = new Date().toISOString()
  db.runSql(`INSERT INTO team_kb_config (team_id, visibility, default_access_level, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, [config.teamId, config.visibility, config.defaultAccessLevel, now, now])
  db.runSql(`INSERT INTO team_kb_members (user_id, team_id, access_level, joined_at) VALUES (?, ?, ?, ?)`, [creatorId, config.teamId, 'admin', now])
}

export function checkUserAccess(db: DatabaseManager, userId: string, teamId: string, requiredLevel: 'read' | 'write' | 'admin'): boolean {
  const rows = db.querySql<any>('SELECT access_level FROM team_kb_members WHERE user_id = ? AND team_id = ?', [userId, teamId])
  const row = rows[0]
  if (!row) {
    const config = db.queryOneSql<any>('SELECT visibility, default_access_level FROM team_kb_config WHERE team_id = ?', [teamId])
    if (config && config.visibility === 'shared') return requiredLevel === 'read'
    return false
  }
  const accessLevels = { read: 1, write: 2, admin: 3 }
  return accessLevels[row.access_level] >= accessLevels[requiredLevel]
}

export function searchTeamKb(db: DatabaseManager, userId: string, teamId: string, query: SearchFunctionsQuery) {
  if (!checkUserAccess(db, userId, teamId, 'read')) return { total: 0, results: [] }
  return searchFunctions(db, query)
}

export async function contributeToTeamKb(db: DatabaseManager, userId: string, teamId: string, data: any): Promise<string> {
  if (!checkUserAccess(db, userId, teamId, 'write')) throw new Error('Insufficient permissions')
  const id = await contributeFunction(db, { ...data, userId })
  db.runSql(`UPDATE function_kb SET team_id = ? WHERE id = ?`, [teamId, id])
  return id
}
