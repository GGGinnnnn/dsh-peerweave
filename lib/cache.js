/**
 * Peer-scoped offline cache for Peerweave.
 *
 * The cache is deliberately separate from `state.json`: it can grow to many
 * megabytes and must never block the identity vault or the permission audit.
 * Every file is private to the profile (the parent directory is chmod 0700).
 */
import { join } from 'node:path'
import { ensurePrivateDir, readJsonFile, writeJsonAtomic } from './util.js'

const CACHE_VERSION = 1
const MAX_CACHE_CHARS = 32 * 1024 * 1024
const MAX_FILE_CHARS = 2 * 1024 * 1024

function safePeerId(value) {
  return String(value || '').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 96) || 'peer'
}

function fresh(peerId) {
  return {
    version: CACHE_VERSION,
    peerId,
    syncedAt: 0,
    history: null,
    sessions: {},
    files: { workspaces: [], listings: {}, files: {} },
  }
}

function cacheSize(data) {
  try {
    return JSON.stringify(data).length
  } catch {
    return MAX_CACHE_CHARS + 1
  }
}

function prune(data) {
  if (cacheSize(data) <= MAX_CACHE_CHARS) return
  const sessions = Object.entries(data.sessions || {})
    .sort((left, right) => Number(right[1]?.updatedAt || right[1]?.time || 0) - Number(left[1]?.updatedAt || left[1]?.time || 0))
  while (sessions.length > 4) {
    delete data.sessions[sessions.pop()[0]]
    if (cacheSize(data) <= MAX_CACHE_CHARS) return
  }
  const files = Object.entries(data.files?.files || {})
  while (files.length > 0 && cacheSize(data) > MAX_CACHE_CHARS) {
    delete data.files.files[files.shift()[0]]
  }
  const listings = Object.entries(data.files?.listings || {})
  while (listings.length > 8 && cacheSize(data) > MAX_CACHE_CHARS) {
    delete data.files.listings[listings.shift()[0]]
  }
}

export class PeerCache {
  constructor(dir) {
    this.dir = dir
    this.memory = new Map()
    this.loading = new Map()
    this.writing = new Map()
  }

  file(peerId) {
    return join(this.dir, `${safePeerId(peerId)}.json`)
  }

  async load(peerId) {
    const key = safePeerId(peerId)
    if (this.memory.has(key)) return this.memory.get(key)
    if (this.loading.has(key)) return this.loading.get(key)
    const promise = (async () => {
      await ensurePrivateDir(this.dir)
      const stored = await readJsonFile(this.file(peerId), null)
      const data = stored && typeof stored === 'object' ? stored : fresh(peerId)
      data.version = CACHE_VERSION
      data.peerId = peerId
      if (!data.sessions || typeof data.sessions !== 'object') data.sessions = {}
      if (!data.files || typeof data.files !== 'object') data.files = { workspaces: [], listings: {}, files: {} }
      if (!Array.isArray(data.files.workspaces)) data.files.workspaces = []
      if (!data.files.listings || typeof data.files.listings !== 'object') data.files.listings = {}
      if (!data.files.files || typeof data.files.files !== 'object') data.files.files = {}
      this.memory.set(key, data)
      this.loading.delete(key)
      return data
    })().catch((error) => {
      this.loading.delete(key)
      throw error
    })
    this.loading.set(key, promise)
    return promise
  }

  peek(peerId) {
    return this.memory.get(safePeerId(peerId)) || null
  }

  async summary(peerId) {
    const data = this.peek(peerId) || await this.load(peerId).catch(() => null)
    if (!data) return { syncedAt: 0, sessions: 0, files: 0 }
    return {
      syncedAt: Number(data.syncedAt) || 0,
      sessions: Object.keys(data.sessions || {}).length,
      files: Object.keys(data.files?.files || {}).length + Object.keys(data.files?.listings || {}).length,
    }
  }

  async update(peerId, mutate) {
    const key = safePeerId(peerId)
    const previous = this.writing.get(key) || Promise.resolve()
    const next = previous.then(async () => {
      const data = await this.load(peerId)
      const result = await mutate(data)
      data.syncedAt = Math.max(Number(data.syncedAt) || 0, Date.now())
      prune(data)
      await writeJsonAtomic(this.file(peerId), data)
      return result
    })
    this.writing.set(key, next.catch(() => {}))
    return next
  }

  async putHistory(peerId, history) {
    return this.update(peerId, (data) => {
      data.history = history
      return true
    })
  }

  async putSession(peerId, sessionId, detail) {
    return this.update(peerId, (data) => {
      data.sessions[String(sessionId)] = detail
      return true
    })
  }

  async putWorkspaces(peerId, workspaces) {
    return this.update(peerId, (data) => {
      data.files.workspaces = Array.isArray(workspaces) ? workspaces : []
      return true
    })
  }

  async putListing(peerId, workspaceId, path, listing) {
    return this.update(peerId, (data) => {
      data.files.listings[`${workspaceId || 'shared'}|${path || ''}`] = listing
      return true
    })
  }

  async putFile(peerId, workspaceId, path, file) {
    const encoded = file && (file.text || file.data) ? String(file.text || file.data) : ''
    if (encoded.length > MAX_FILE_CHARS) return false
    return this.update(peerId, (data) => {
      data.files.files[`${workspaceId || 'shared'}|${path || ''}`] = {
        ...file,
        cachedAt: Date.now(),
      }
      return true
    })
  }

  hasHistory(peerId) {
    return Boolean(this.peek(peerId)?.history)
  }

  history(peerId) {
    return this.peek(peerId)?.history || null
  }

  session(peerId, sessionId) {
    return this.peek(peerId)?.sessions?.[String(sessionId)] || null
  }

  workspaces(peerId) {
    return this.peek(peerId)?.files?.workspaces || null
  }

  listing(peerId, workspaceId, path) {
    return this.peek(peerId)?.files?.listings?.[`${workspaceId || 'shared'}|${path || ''}`] || null
  }

  fileContent(peerId, workspaceId, path) {
    return this.peek(peerId)?.files?.files?.[`${workspaceId || 'shared'}|${path || ''}`] || null
  }
}
