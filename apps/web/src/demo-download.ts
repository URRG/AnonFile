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

async function verifiedCandidatePng(page: { candidatePngBase64: string; candidatePngSha256: string }): Promise<Uint8Array> {
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
  return bytes
}

type RasterPage = { width: number; height: number; rgb: Uint8Array }

function canvasFor(width: number, height: number): OffscreenCanvas | HTMLCanvasElement {
  if (typeof globalThis.OffscreenCanvas === 'function') return new OffscreenCanvas(width, height)
  const canvas = globalThis.document?.createElement?.('canvas')
  if (!canvas) throw new Error('Browser image decoding and canvas support are required to build this reviewed PDF.')
  canvas.width = width
  canvas.height = height
  return canvas
}

async function reviewedRasterPage(page: { width: number; height: number; candidatePngBase64: string; candidatePngSha256: string;
  manualRegions: { x0: number; x1: number; y0: number; y1: number }[] }): Promise<RasterPage> {
  if (typeof globalThis.createImageBitmap !== 'function') {
    throw new Error('Browser image decoding and canvas support are required to build this reviewed PDF.')
  }
  const png = await verifiedCandidatePng(page)
  let bitmap: ImageBitmap
  try { bitmap = await globalThis.createImageBitmap(new Blob([copiedBuffer(png)], { type: 'image/png' })) }
  catch { throw new Error('The reviewed candidate PNG could not be decoded locally.') }
  try {
    if (bitmap.width !== page.width || bitmap.height !== page.height) throw new Error('The reviewed candidate PNG dimensions do not match the review page.')
    const canvas = canvasFor(bitmap.width, bitmap.height)
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw new Error('Browser image decoding and canvas support are required to build this reviewed PDF.')
    context.drawImage(bitmap, 0, 0)
    const rgba = context.getImageData(0, 0, bitmap.width, bitmap.height).data
    for (const region of page.manualRegions) {
      if (!Number.isSafeInteger(region.x0) || !Number.isSafeInteger(region.x1) || !Number.isSafeInteger(region.y0) || !Number.isSafeInteger(region.y1) ||
          region.x0 < 0 || region.y0 < 0 || region.x1 <= region.x0 || region.y1 <= region.y0 || region.x1 > bitmap.width || region.y1 > bitmap.height) {
        throw new Error('A reviewed redaction region is invalid.')
      }
      for (let y = region.y0; y < region.y1; y++) for (let x = region.x0; x < region.x1; x++) {
        const offset = (y * bitmap.width + x) * 4
        if (rgba[offset] !== 0 || rgba[offset + 1] !== 0 || rgba[offset + 2] !== 0 || rgba[offset + 3] !== 255) {
          throw new Error('A reviewed redaction is not opaque black in the candidate pixels; no PDF was created.')
        }
      }
    }
    const rgb = new Uint8Array(bitmap.width * bitmap.height * 3)
    for (let source = 0, target = 0; source < rgba.length; source += 4) {
      if (rgba[source + 3] !== 255) {
        throw new Error('The reviewed candidate PNG contains transparency and cannot be faithfully rebuilt as a PDF.')
      }
      rgb[target++] = rgba[source]
      rgb[target++] = rgba[source + 1]
      rgb[target++] = rgba[source + 2]
    }
    return { width: bitmap.width, height: bitmap.height, rgb }
  } finally { bitmap.close() }
}

async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis.CompressionStream !== 'function') {
    throw new Error('Browser compression support is required to build this reviewed PDF.')
  }
  try {
    const stream = new Blob([copiedBuffer(bytes)]).stream().pipeThrough(new CompressionStream('deflate'))
    return new Uint8Array(await new Response(stream).arrayBuffer())
  } catch { throw new Error('The reviewed PDF could not be compressed locally.') }
}

function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0)
  const result = new Uint8Array(length)
  let offset = 0
  for (const part of parts) { result.set(part, offset); offset += part.length }
  return result
}

const ascii = (value: string) => new TextEncoder().encode(value)

function copiedBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length)
  new Uint8Array(buffer).set(bytes)
  return buffer
}

async function rasterPdf(pages: RasterPage[]): Promise<Uint8Array> {
  const objects = new Map<number, Uint8Array>()
  const pageIds = pages.map((_, index) => 3 + index * 3)
  objects.set(1, ascii('<< /Type /Catalog /Pages 2 0 R >>'))
  objects.set(2, ascii(`<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`))
  for (let index = 0; index < pages.length; index++) {
    const page = pages[index]
    const pageId = pageIds[index]
    const contentId = pageId + 1
    const imageId = pageId + 2
    const compressed = await deflate(page.rgb)
    const content = ascii(`q\n${page.width} 0 0 ${page.height} 0 0 cm\n/Im0 Do\nQ\n`)
    objects.set(pageId, ascii(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${page.width} ${page.height}] /Resources << /XObject << /Im0 ${imageId} 0 R >> >> /Contents ${contentId} 0 R >>`))
    objects.set(contentId, concat([ascii(`<< /Length ${content.length} >>\nstream\n`), content, ascii('endstream')]))
    objects.set(imageId, concat([ascii(`<< /Type /XObject /Subtype /Image /Width ${page.width} /Height ${page.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length ${compressed.length} >>\nstream\n`), compressed, ascii('\nendstream')]))
  }
  const output: Uint8Array[] = [ascii('%PDF-1.4\n%\xFF\xFF\xFF\xFF\n')]
  const offsets = [0]
  let position = output[0].length
  for (let id = 1; id <= objects.size; id++) {
    offsets[id] = position
    const object = concat([ascii(`${id} 0 obj\n`), objects.get(id)!, ascii('\nendobj\n')])
    output.push(object)
    position += object.length
  }
  const xref = position
  output.push(ascii(`xref\n0 ${objects.size + 1}\n0000000000 65535 f \n${offsets.slice(1).map(offset => `${String(offset).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.size + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`))
  const pdf = concat(output)
  if (pdf.length > 10_000_000) throw new Error('The reviewed PDF exceeds the 10 MB demo download limit.')
  return pdf
}

/**
 * Build a local copy of one synthetic, unqualified preview candidate. This
 * intentionally never reads the source PNG, source text, or any release API.
 */
export async function prepareDemoCandidateFile(item: BatchDocument): Promise<DemoCandidateFile> {
  if (item.kind === 'pdf') {
    const pages = item.mediaPreview?.pages
    if (pages?.some(page => page.manualRegions?.length > 0)) {
      if (!pages.length) throw new Error('No reviewed PDF pages are available.')
      const rasterPages = await Promise.all(pages.map(reviewedRasterPage))
      return { name: nameFor(item.name, 'pdf'), mimeType: 'application/pdf', bytes: await rasterPdf(rasterPages) }
    }
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
    const bytes = await verifiedCandidatePng(page)
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
