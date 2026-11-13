/**
 * Peerweave shared helpers: encodings, key handling, password sealing,
 * encrypted-frame primitives and safe path resolution.
 *
 * No DSH imports live here so the protocol can be unit-tested and driven by a
 * stand-alone peer process.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  scrypt as scryptCallback,
  sign as signBytes,
  timingSafeEqual,
  verify as verifyBytes,
} from 'node:crypto'
import { mkdir, readFile, realpath, rename, stat, writeFile, unlink } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { networkInterfaces } from 'node:os'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

export const PROTOCOL_VERSION = 1
export const HANDSHAKE_MAX_FRAME = 64 * 1024
// Sharing is chunked over the wire, so one frame never carries a whole file.
export const FILE_CHUNK_BYTES = 8 * 1024 * 1024
export const MAX_LINK_FRAME = FILE_CHUNK_BYTES * 2 + 1024 * 1024
// A single inline read stays bounded; larger files transfer through chunks.
export const MAX_INLINE_READ_BYTES = 8 * 1024 * 1024
export const MAX_FILE_HARD_LIMIT = 2 * 1024 * 1024 * 1024
export const DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024

const ED25519_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const ED25519_PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const X25519_PUBLIC_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
const X25519_PRIVATE_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

export function b64u(value) {
  return Buffer.from(value).toString('base64url')
}

export function unb64u(text) {
  return Buffer.from(String(text), 'base64url')
}

export function b64(value) {
  return Buffer.from(value).toString('base64')
}

export function unb64(text) {
  return Buffer.from(String(text), 'base64')
}

export function hex(value) {
  return Buffer.from(value).toString('hex')
}

export function unhex(text) {
  return Buffer.from(String(text), 'hex')
}

export function sha256(...parts) {
  const hash = createHash('sha256')
  for (const part of parts) hash.update(toBuf(part))
  return hash.digest()
}

export function sha256hex(...parts) {
  return sha256(...parts).toString('hex')
}

export function hmacSha256(key, data) {
  return createHmac('sha256', toBuf(key)).update(toBuf(data)).digest()
}

export function timingSafeEq(a, b) {
  const left = toBuf(a)
  const right = toBuf(b)
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

export function toBuf(value) {
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  if (typeof value === 'string') return Buffer.from(value, 'utf8')
  return Buffer.from(JSON.stringify(value), 'utf8')
}

/** Length-prefixed domain hash; avoids JSON key-order ambiguity. */
export function domainHash(domain, parts) {
  const chunks = [toBuf(domain)]
  for (const part of parts) {
    const buf = toBuf(part)
    const len = Buffer.allocUnsafe(4)
    len.writeUInt32BE(buf.length, 0)
    chunks.push(len, buf)
  }
  return sha256(...chunks)
}

export function randomHex(bytes = 16) {
  return randomBytes(bytes).toString('hex')
}

export function randomB64u(bytes = 32) {
  return randomBytes(bytes).toString('base64url')
}

// ---------------------------------------------------------------------------
// Identity (Ed25519) and ephemeral (X25519) keys
// ---------------------------------------------------------------------------

export function generateIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const publicRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  return {
    publicRaw: Buffer.from(publicRaw),
    privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
  }
}

export function privateKeyFromPem(pem) {
  return createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' })
}

export function publicKeyFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([ED25519_PUBLIC_PREFIX, toBuf(raw)]), format: 'der', type: 'spki' })
}

export function signWith(privateKey, data) {
  return signBytes(null, toBuf(data), privateKey)
}

export function verifyWith(publicKey, data, signature) {
  try {
    return verifyBytes(null, toBuf(data), publicKey, toBuf(signature))
  } catch {
    return false
  }
}

export function fingerprint(raw) {
  return sha256(toBuf(raw)).toString('hex')
}

export function shortFingerprint(fp) {
  const text = String(fp || '')
  const groups = []
  for (let i = 0; i + 4 <= text.length && groups.length < 4; i += 4) groups.push(text.slice(i, i + 4))
  return groups.length === 4 ? `PW-${groups.join('-')}` : 'PW-????'
}

export function generateEphemeral() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  const publicRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  const privateRaw = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32)
  return { privateRaw: Buffer.from(privateRaw), publicRaw: Buffer.from(publicRaw) }
}

export function x25519FromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([X25519_PUBLIC_PREFIX, toBuf(raw)]), format: 'der', type: 'spki' })
}

export function x25519PrivateFromRaw(raw) {
  return createPrivateKey({ key: Buffer.concat([X25519_PRIVATE_PREFIX, toBuf(raw)]), format: 'der', type: 'pkcs8' })
}

export function x25519Shared(privateRaw, peerPublicRaw) {
  return diffieHellman({ privateKey: x25519PrivateFromRaw(privateRaw), publicKey: x25519FromRaw(peerPublicRaw) })
}

export function hkdf32(secret, salt, info) {
  return Buffer.from(hkdfSync('sha256', toBuf(secret), toBuf(salt), toBuf(info), 32))
}

// ---------------------------------------------------------------------------
// AES-256-GCM frames: 12-byte nonce = 4 zero bytes + 64-bit big-endian counter.
// ---------------------------------------------------------------------------

export function aesEncrypt(key, counter, aad, plaintext) {
  const nonce = Buffer.alloc(12)
  nonce.writeBigUInt64BE(BigInt(counter), 4)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  if (aad) cipher.setAAD(toBuf(aad))
  const body = Buffer.concat([cipher.update(toBuf(plaintext)), cipher.final()])
  return Buffer.concat([body, cipher.getAuthTag()])
}

export function aesDecrypt(key, counter, aad, sealed) {
  const buf = toBuf(sealed)
  if (buf.length < 16) throw new Error('frame too short')
  const nonce = Buffer.alloc(12)
  nonce.writeBigUInt64BE(BigInt(counter), 4)
  const tag = buf.subarray(buf.length - 16)
  const body = buf.subarray(0, buf.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  if (aad) decipher.setAAD(toBuf(aad))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}

// ---------------------------------------------------------------------------
// Password derivation: scrypt -> master key; identity PEM sealed with AES-GCM.
// ---------------------------------------------------------------------------

export const SCRYPT_PARAMS = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 32 })

export async function deriveMaster(password, saltB64, params = SCRYPT_PARAMS) {
  const salt = unb64(saltB64)
  return Buffer.from(await scrypt(String(password), salt, params.keylen, { N: params.N, r: params.r, p: params.p, maxmem: 64 * 1024 * 1024 }))
}

export function stateKey(master) {
  return hkdf32(master, 'peerweave-state-v1', 'identity-seal')
}

export function sealString(master, plaintext) {
  const key = stateKey(master)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([cipher.update(Buffer.from(String(plaintext), 'utf8')), cipher.final()])
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }
}

export function openString(master, sealed) {
  if (!sealed || !sealed.iv || !sealed.tag || !sealed.data) throw new Error('sealed value is incomplete')
  const key = stateKey(master)
  const decipher = createDecipheriv('aes-256-gcm', key, unb64(sealed.iv))
  decipher.setAuthTag(unb64(sealed.tag))
  const plain = Buffer.concat([decipher.update(unb64(sealed.data)), decipher.final()])
  return plain.toString('utf8')
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

export async function readJsonFile(file, fallback) {
  try {
    const text = await readFile(file, 'utf8')
    return JSON.parse(text)
  } catch (error) {
    if (error && error.code === 'ENOENT') return fallback
    throw error
  }
}

export async function writeJsonAtomic(file, value) {
  await mkdir(dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${randomHex(6)}.tmp`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  try {
    await rename(tmp, file)
  } catch (error) {
    await unlink(tmp).catch(() => {})
    throw error
  }
}

export function isInside(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate))
  if (rel === '') return true
  if (isAbsolute(rel)) return false
  return !rel.split(sep).includes('..')
}

export function normalizeRelative(input) {
  const text = String(input ?? '').replace(/\\/g, '/').trim()
  if (text === '' || text === '.') return ''
  if (text.includes('\0')) throw new Error('invalid path')
  if (text.startsWith('/')) throw new Error('path must be relative')
  if (/^[a-zA-Z]:/.test(text)) throw new Error('path must be relative')
  const parts = text.split('/').filter((part) => part !== '' && part !== '.')
  if (parts.some((part) => part === '..')) throw new Error('path must not contain ..')
  return parts.join('/')
}

export async function safeResolveInside(root, relInput) {
  try {
    const rel = normalizeRelative(relInput)
    const realRoot = await realpath(resolve(root))
    const abs = resolve(realRoot, rel)
    if (!isInside(realRoot, abs)) throw new Error('path escapes the shared root')
    return { realRoot, abs, rel }
  } catch (error) {
    if (!(error && error.code)) {
      const failure = new Error(error && error.message ? error.message : 'invalid path')
      failure.code = 'invalid-path'
      throw failure
    }
    throw error
  }
}

export async function statSafe(root, relInput) {
  const { realRoot, abs, rel } = await safeResolveInside(root, relInput)
  let target = abs
  try {
    target = await realpath(abs)
  } catch (error) {
    if (error && error.code === 'ENOENT') return { exists: false, realRoot, rel }
    throw error
  }
  if (!isInside(realRoot, target)) throw new Error('path escapes the shared root')
  const info = await stat(target)
  return { exists: true, realRoot, abs: target, rel, info }
}

export async function ensurePrivateDir(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 })
}

export function sleep(ms) {
  return new Promise((done) => setTimeout(done, ms))
}

export function detectLanIPv4() {
  try {
    const nets = networkInterfaces()
    for (const list of Object.values(nets)) {
      for (const net of list || []) {
        if (net.family === 'IPv4' && !net.internal && net.address && !net.address.startsWith('169.254.')) return net.address
      }
    }
  } catch {
    /* ignore */
  }
  return '127.0.0.1'
}

export function normalizeHostName(host) {
  return String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '')
}

export function isLoopbackHostname(host) {
  const name = normalizeHostName(host)
  if (name === 'localhost' || name.endsWith('.localhost')) return true
  if (name === '::1') return true
  const match = name.match(/^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!match) return false
  return match.slice(1).every((part) => Number(part) >= 0 && Number(part) <= 255)
}

export function errorText(error) {
  return String((error && (error.message || error.code)) || error || 'unknown error')
}

export async function fileSizeOf(path) {
  try {
    return (await stat(path)).size
  } catch {
    return null
  }
}
