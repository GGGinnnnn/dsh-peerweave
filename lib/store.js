/**
 * Durable Peerweave state: identity key material sealed with the install
 * password, trusted peers, single-use invites and the permission audit trail.
 */
import { join } from 'node:path'
import {
  DEFAULT_MAX_FILE_BYTES,
  MAX_FILE_HARD_LIMIT,
  ensurePrivateDir,
  readJsonFile,
  writeJsonAtomic,
} from './util.js'

export const STATE_VERSION = 1
export const TIER_NAMES = Object.freeze({
  0: 'linked',
  1: 'history',
  2: 'files',
  3: 'chat',
})

export function createDefaultState() {
  return {
    version: STATE_VERSION,
    createdAt: Date.now(),
    instanceId: '',
    identity: null,
    password: null,
    settings: {
      displayName: '',
      listenPort: 41337,
      bindHost: '0.0.0.0',
      advertiseHost: '',
      sharedRoot: '',
      maxFileBytes: DEFAULT_MAX_FILE_BYTES,
      autoConnect: true,
      reverseSsh: { enabled: false, target: '', bindPort: 0, extraArgs: '' },
      relayServer: { enabled: false, port: 41338, token: '' },
      relayClient: { host: '', port: 41338, token: '' },
    },
    peers: [],
    invites: [],
    audit: [],
  }
}

export class PeerweaveStore {
  constructor(dataDir, config = {}) {
    this.dir = dataDir
    this.file = join(dataDir, 'state.json')
    this.config = config
    this.state = null
    this.fresh = false
    this.writing = Promise.resolve()
  }

  async load() {
    await ensurePrivateDir(this.dir)
    const fallback = createDefaultState()
    const loaded = await readJsonFile(this.file, null)
    this.fresh = loaded === null
    const state = loaded && typeof loaded === 'object' ? loaded : fallback
    const base = createDefaultState()
    state.version = STATE_VERSION
    state.instanceId = String(state.instanceId || '')
    state.settings = { ...base.settings, ...(state.settings || {}) }
    for (const key of ['reverseSsh', 'relayServer', 'relayClient']) {
      state.settings[key] = { ...base.settings[key], ...(state.settings[key] && typeof state.settings[key] === 'object' ? state.settings[key] : {}) }
    }
    if (state.settings.bindHost !== '::') state.settings.bindHost = '0.0.0.0'
    if (!Array.isArray(state.peers)) state.peers = []
    if (!Array.isArray(state.invites)) state.invites = []
    if (!Array.isArray(state.audit)) state.audit = []
    if (!Number.isFinite(state.settings.listenPort) || state.settings.listenPort <= 0) state.settings.listenPort = base.settings.listenPort
    state.settings.maxFileBytes = clampBytes(state.settings.maxFileBytes)
    state.peers = state.peers
      .filter((peer) => peer && typeof peer.id === 'string' && typeof peer.publicKey === 'string')
      .map((peer) => normalizePeer(peer))
    this.state = state
    return state
  }

  get settings() {
    return this.state.settings
  }

  get identity() {
    return this.state.identity
  }

  get passwordSet() {
    return Boolean(this.state.password && this.state.identity && this.state.identity.sealedPrivate)
  }

  peers() {
    return this.state.peers
  }

  peer(id) {
    return this.state.peers.find((peer) => peer.id === id)
  }

  peerByPublicKey(publicRaw) {
    const target = Buffer.from(publicRaw).toString('base64')
    return this.state.peers.find((peer) => peer.publicKey === target)
  }

  upsertPeer(peer) {
    const existing = this.peer(peer.id)
    if (existing) {
      Object.assign(existing, peer, { addedAt: existing.addedAt || peer.addedAt || Date.now() })
      return existing
    }
    const record = normalizePeer({ ...peer, addedAt: peer.addedAt || Date.now() })
    this.state.peers.push(record)
    return record
  }

  removePeer(id) {
    const before = this.state.peers.length
    this.state.peers = this.state.peers.filter((peer) => peer.id !== id)
    return before !== this.state.peers.length
  }

  invites() {
    return this.state.invites
  }

  async save() {
    const snapshot = JSON.stringify(this.state, null, 2)
    this.writing = this.writing.then(async () => {
      await writeJsonAtomic(this.file, JSON.parse(snapshot))
    })
    return this.writing
  }
}

export function normalizePeer(peer) {
  const tier = Number(peer.tier)
  const transport = peer.transport === 'ssh' ? 'ssh' : peer.transport === 'relay' ? 'relay' : 'tcp'
  return {
    id: String(peer.id),
    publicKey: String(peer.publicKey),
    name: String(peer.name || 'DSH peer').slice(0, 80),
    instanceId: String(peer.instanceId || ''),
    host: String(peer.host || ''),
    port: Number(peer.port) || 0,
    listenPort: Number(peer.listenPort) || 0,
    transport,
    sshTarget: String(peer.sshTarget || ''),
    sshRemotePort: Number(peer.sshRemotePort) || 0,
    relay: normalizeRelay(peer.relay),
    autoDial: Boolean(peer.autoDial),
    tier: Number.isInteger(tier) && tier >= 0 && tier <= 3 ? tier : 0,
    addedAt: Number(peer.addedAt) || Date.now(),
    lastSeenAt: Number(peer.lastSeenAt) || 0,
    remoteTier: Number.isInteger(Number(peer.remoteTier)) ? Number(peer.remoteTier) : -1,
    remoteMaxFileBytes: Number(peer.remoteMaxFileBytes) || 0,
    remoteSharedLabel: String(peer.remoteSharedLabel || ''),
    remoteModel: String(peer.remoteModel || ''),
    guestSessionId: peer.guestSessionId ? String(peer.guestSessionId) : '',
    guestWorkspaceId: peer.guestWorkspaceId ? String(peer.guestWorkspaceId) : '',
  }
}

export function normalizeRelay(relay) {
  if (!relay || typeof relay !== 'object') return null
  const host = String(relay.host || '').trim()
  const room = String(relay.room || '').toLowerCase()
  const role = relay.role === 'host' ? 'host' : relay.role === 'join' ? 'join' : ''
  if (!host || !/^[a-f0-9]{16,64}$/.test(room) || !role) return null
  return {
    host,
    port: Number(relay.port) || 41338,
    room,
    token: String(relay.token || ''),
    role,
  }
}

export function clampBytes(value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number <= 0) return DEFAULT_MAX_FILE_BYTES
  return Math.min(Math.max(Math.floor(number), 1024), MAX_FILE_HARD_LIMIT)
}
