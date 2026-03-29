import { z } from 'zod'

export const TOOL_SURFACE_ROLE_VALUES = [
  'primary',
  'compatibility',
  'export_only',
  'renderer_helper',
] as const

export const ToolSurfaceRoleSchema = z.enum(TOOL_SURFACE_ROLE_VALUES)

export type ToolSurfaceRole = z.infer<typeof ToolSurfaceRoleSchema>

export function buildPreferredPrimaryTools(
  role: ToolSurfaceRole,
  preferredPrimaryTools: string[]
) {
  return role === 'primary' ? [] : preferredPrimaryTools
}
