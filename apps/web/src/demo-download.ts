import type { BatchDocument } from './api'

export type DemoCandidateFile = { name: string; mimeType: string; bytes: Uint8Array }

function decodeBase64(value: string): Uint8Array {
  if (!value || value.length > 13_333_336 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('The synthetic candidate is malformed; nothing was downloaded.')
  }
  let binary: string
  try { binary = atob(value) } catch { throw new Error('The synthetic candidate is malformed; nothing was downloaded.') }
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function nameFor(original: string, extension: string): string {
  const stem = original.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120)
  if (!stem || stem === '.' || stem === '..') throw new Error('The synthetic candidate filename is invalid.')
  return `${stem}.candidate.${extension}`
}

/**
 * Build a local copy of one synthetic, unqualified preview candidate. This
 * intentionally never reads the source PNG, source text, or any release API.
 */
export async function prepareDemoCandidateFile(item: BatchDocument): Promise<DemoCandidateFile> {
  if (item.kind === 'pdf') {
    const evidence = item.mediaPreview?.pdfRasterEvidence
    const encoded = item.mediaPreview?.candidatePdfBase64
    if (!evidence || !encoded || evidence.sourceObjectsCopied !== false || evidence.pages !== item.mediaPreview?.pages.length) {
      throw new Error('No rebuilt raster PDF candidate is available.')
    }
    const bytes = decodeBase64(encoded)
    if (bytes.length !== evidence.bytes || bytes.length > 10_000_000 ||
        !new TextDecoder('ascii').decode(bytes.subarray(0, 5)).startsWith('%PDF-') ||
        !new TextDecoder('ascii').decode(bytes.subarray(-128)).includes('%%EOF')) {
      throw new Error('The rebuilt PDF candidate does not match its declared size or format.')
    }
    if (!globalThis.crypto?.subtle) throw new Error('Browser cryptography is required to verify the rebuilt PDF candidate.')
    const buffer = new ArrayBuffer(bytes.length)
    new Uint8Array(buffer).set(bytes)
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buffer))
    const actual = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
    if (actual !== evidence.sha256) throw new Error('The rebuilt PDF candidate failed its integrity check.')
    return { name: nameFor(item.name, 'pdf'), mimeType: 'application/pdf', bytes }
  }
  if (item.kind === 'image') {
    const page = item.mediaPreview?.pages[0]
    if (!page || item.mediaPreview?.pages.length !== 1) throw new Error('No image candidate is available.')
    const bytes = decodeBase64(page.candidatePngBase64)
    if (bytes.length < 24 || ![137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => bytes[index] === byte)) {
      throw new Error('The image candidate is not a PNG.')
    }
    if (!globalThis.crypto?.subtle || !/^[0-9a-f]{64}$/.test(page.candidatePngSha256)) {
      throw new Error('The image candidate lacks integrity evidence.')
    }
    const buffer = new ArrayBuffer(bytes.length)
    new Uint8Array(buffer).set(bytes)
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buffer))
    const actual = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
    if (actual !== page.candidatePngSha256) throw new Error('The image candidate failed its integrity check.')
    return { name: nameFor(item.name, 'png'), mimeType: 'image/png', bytes }
  }
  const types: Record<'text' | 'csv' | 'json' | 'jsonl', { extension: string; mimeType: string }> = {
    text: { extension: 'txt', mimeType: 'text/plain;charset=utf-8' },
    csv: { extension: 'csv', mimeType: 'text/csv;charset=utf-8' },
    json: { extension: 'json', mimeType: 'application/json' },
    jsonl: { extension: 'jsonl', mimeType: 'application/x-ndjson' },
  }
  const type = types[item.kind]
  if (!type || typeof item.candidateText !== 'string') throw new Error('No text candidate is available.')
  return { name: nameFor(item.name, type.extension), mimeType: type.mimeType,
    bytes: new TextEncoder().encode(item.candidateText) }
}

/** Save only the synthetic review candidate, never a source file or an authorized release. */
export async function downloadDemoCandidate(item: BatchDocument): Promise<void> {
  const candidate = await prepareDemoCandidateFile(item)
  const link = globalThis.document.createElement('a')
  const blobBuffer = new ArrayBuffer(candidate.bytes.length)
  new Uint8Array(blobBuffer).set(candidate.bytes)
  const url = URL.createObjectURL(new Blob([blobBuffer], { type: candidate.mimeType }))
  link.href = url
  link.download = candidate.name
  link.hidden = true
  globalThis.document.body.append(link)
  try { link.click() } finally {
    link.remove()
    globalThis.setTimeout(() => URL.revokeObjectURL(url), 30_000)
  }
}
