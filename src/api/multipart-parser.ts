/**
 * Multipart Form Data Parser
 * Simple parser for multipart/form-data requests
 */

export interface MultipartFile {
  fieldname: string
  filename: string
  data: Buffer
  mimetype: string
}

export interface ParsedMultipart {
  files: MultipartFile[]
  fields: Record<string, string>
}

/**
 * Parse multipart/form-data request
 */
export function parseMultipart(
  body: Buffer,
  contentType: string
): ParsedMultipart {
  const result: ParsedMultipart = {
    files: [],
    fields: {},
  }

  // Extract boundary from content-type
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i)
  if (!boundaryMatch) {
    throw new Error('Invalid multipart content-type: missing boundary')
  }

  const boundary = boundaryMatch[1] || boundaryMatch[2]
  const boundaryBuffer = Buffer.from(`--${boundary}`)
  
  // Split body by boundary
  const parts: Buffer[] = []
  let start = 0
  while (true) {
    const pos = body.indexOf(boundaryBuffer, start)
    if (pos === -1) break
    parts.push(body.slice(start, pos))
    start = pos + boundaryBuffer.length
  }

  for (const part of parts) {
    // Skip empty parts and epilogue
    if (part.length === 0 || part.toString().startsWith('--\r\n')) {
      continue
    }

    // Remove leading CRLF
    let cleanPart = part
    if (cleanPart[0] === 0x0d && cleanPart[1] === 0x0a) {
      cleanPart = cleanPart.slice(2)
    }

    // Split headers and body
    const headerEndIndex = cleanPart.indexOf(Buffer.from('\r\n\r\n'))
    if (headerEndIndex === -1) {
      continue
    }

    const headerBuffer = cleanPart.slice(0, headerEndIndex)
    const bodyBuffer = cleanPart.slice(headerEndIndex + 4)

    // Parse headers
    const headers = parseHeaders(headerBuffer)
    const contentDisposition = headers['content-disposition']

    if (!contentDisposition) {
      continue
    }

    // Parse content-disposition
    const dispMatch = contentDisposition.match(
      /name="([^"]+)"(?:; filename="([^"]+)")?/
    )
    if (!dispMatch) {
      continue
    }

    const fieldName = dispMatch[1]
    const filename = dispMatch[2]

    if (filename) {
      // This is a file
      const mimetype = headers['content-type'] || 'application/octet-stream'
      result.files.push({
        fieldname: fieldName,
        filename,
        data: bodyBuffer,
        mimetype,
      })
    } else {
      // This is a regular field
      result.fields[fieldName] = bodyBuffer.toString('utf8')
    }
  }

  return result
}

/**
 * Parse headers from buffer
 */
function parseHeaders(headerBuffer: Buffer): Record<string, string> {
  const headers: Record<string, string> = {}
  const headerStr = headerBuffer.toString('utf8')
  const lines = headerStr.split('\r\n')

  for (const line of lines) {
    if (!line.trim()) continue

    const colonIndex = line.indexOf(':')
    if (colonIndex === -1) continue

    const key = line.slice(0, colonIndex).trim().toLowerCase()
    const value = line.slice(colonIndex + 1).trim()
    headers[key] = value
  }

  return headers
}
