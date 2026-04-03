let counter = 0

export const v4 = (): string => {
  counter++
  return `00000000-0000-4000-a000-${counter.toString().padStart(12, '0')}`
}

export const v1 = v4
export const v3 = v4
export const v5 = v4
export const NIL = '00000000-0000-0000-0000-000000000000'
export const MAX = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
export const validate = (uuid: string): boolean => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)
export const version = (_uuid: string): number => 4
export const parse = (_uuid: string): Uint8Array => new Uint8Array(16)
export const stringify = (_arr: Uint8Array): string => v4()
