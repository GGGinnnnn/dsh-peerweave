/**
 * Peerweave Host service: identity/password lifecycle, encrypted listener,
 * trusted peer registry, tiered remote operations, history/files/chat access,
 * SSH tunnels and the local management operations used by the UI and tools.
 */
import net from 'node:net'
import { spawn } from 'node:child_process'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { homedir, hostname } from 'node:os'
import { randomBytes } from 'node:crypto'
import { mkdir, open, readdir, readFile, realpath, rm, stat } from 'node:fs/promises'

import { TIER_NAMES, clampBytes, createDefaultState, PeerweaveStore, normalizeRelay } from './store.js'
import { SecureChannel, runInitiatorHandshake, runResponderHandshake } from './protocol.js'
import { startRelayServer } from './relay-server.js'
import { openRelay } from './relay-client.js'
import {
  FILE_CHUNK_BYTES,
  MAX_FILE_HARD_LIMIT,
  MAX_INLINE_READ_BYTES,
  MAX_LINK_FRAME,
  b64,
  b64u,
  detectLanIPv4,
  deriveMaster,
  errorText,
  fingerprint,
  generateIdentity,
  hmacSha256,
  isInside,
  normalizeRelative,
  openString,
  privateKeyFromPem,
  randomHex,
  safeResolveInside,
  sealString,
  shortFingerprint,
  sleep,
  statSafe,
  timingSafeEq,
  unb64u,
} from './util.js'

const VERSION = '1.1.1'
const DEFAULT_PORT = 41337
const LINK_TIMEOUT = 15000
const TOKEN_TTL_MS = 30 * 60 * 1000
const MIN_PASSWORD = 8
const MAX_PASSWORD = 256
const GRANT_CONFIRM_MS = 10000

function pwError(code, message) {
  const error = new Error(message || code)
  error.code = code
  return error
}

function withTimeout(promise, ms, message) {
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(pwError('timeout', message || 'operation timed out')), ms)
    timer.unref?.()
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

function cleanName(value) {
  return String(value || '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim()
    .slice(0, 80)
}

function sanitizeSegment(value) {
  return String(value || 'peer').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^\.+/, '').slice(0, 60) || 'peer'
}

function normalizeAddress(address) {
  const text = String(address || '')
  if (!text) return ''
  if (text.startsWith('::ffff:')) return text.slice(7)
  if (text === '::1') return '127.0.0.1'
  return text
}

function isLoopbackAddress(address) {
  return normalizeAddress(address).startsWith('127.')
}

function blocksText(content) {
  if (!Array.isArray(content)) return ''
  const parts = []
  for (const block of content) {
    if (!block || typeof block !== 'object') continue
    if (block.type === 'text' && typeof block.text === 'string') parts.push(block.text)
  }
  return parts.join('\n').trim()
}

function isBinaryBuffer(buffer) {
  const sample = buffer.subarray(0, 8192)
  for (const byte of sample) if (byte === 0) return true
  return false
}

function mapWireEvent(event) {
  if (!event || typeof event !== 'object') return null
  if (event.type === 'user/message') {
    return { role: 'user', seq: event.seq, time: event.time, text: blocksText(event.data && event.data.content) }
  }
  if (event.type === 'assistant/message') {
    const message = event.data && event.data.message
    return { role: 'assistant', seq: event.seq, time: event.time, text: blocksText(message && message.content) }
  }
  return null
}

export class PeerweaveService {
  constructor({ ctx, config, log }) {
    this.ctx = ctx
    this.config = config || {}
    this.logger = log || (() => {})
    const home = process.env.DSH_HOME || join(homedir(), '.dsh')
    const profile = process.env.DSH_PROFILE || 'default'
    this.dataDir = this.config.dataDir ? resolve(String(this.config.dataDir)) : join(home, 'peerweave', sanitizeSegment(profile))
    this.store = new PeerweaveStore(this.dataDir)
    this.ready = this.store.load().then(() => this.applyFreshConfig())
    this.identity = null
    this.server = null
    this.serverPort = 0
    this.serverError = ''
    this.links = new Map()
    this.tunnels = new Map()
    this.tokens = new Map()
    this.authState = new Map()
    this.pendingGrants = new Map()
    this.forceResets = new Map()
    this.dialing = new Set()
    this.dialFailures = new Map()
    this.lastDialAt = new Map()
    this.chatChains = new Map()
    this.relayWaiters = new Map()
    this.relayServer = null
    this.relayServerError = ''
    this.reverseTunnel = null
    this.reverseError = ''
    this.reverseTimer = null
    this.autoTimer = null
    this.deps = { controller: null, query: null, workingDirectory: null, registry: null }
    this.disposed = false
    this.auditLimit = 200
  }

  applyFreshConfig() {
    if (!this.store.fresh) return
    const settings = this.store.settings
    if (this.config.listenPort) settings.listenPort = Number(this.config.listenPort) || DEFAULT_PORT
    if (this.config.maxFileBytes) settings.maxFileBytes = clampBytes(this.config.maxFileBytes)
    if (this.config.sharedRoot) settings.sharedRoot = resolve(String(this.config.sharedRoot))
    if (this.config.displayName) settings.displayName = cleanName(this.config.displayName)
    if (this.config.advertiseHost) settings.advertiseHost = String(this.config.advertiseHost)
    if (this.config.autoConnect === false) settings.autoConnect = false
    return this.store.save()
  }

  attach(deps) {
    Object.assign(this.deps, deps || {})
  }

  log(message) {
    try {
      this.logger(message)
    } catch {
      /* ignore */
    }
  }

  instanceId() {
    if (!this.store.state.instanceId) {
      this.store.state.instanceId = randomHex(16)
      this.store.save().catch(() => {})
    }
    return this.store.state.instanceId
  }

  displayName() {
    return cleanName(this.store.settings.displayName) || cleanName(hostname()) || 'DSH peer'
  }

  sharedRootPath() {
    const configured = this.store.settings.sharedRoot
    if (configured) return resolve(configured)
    const workingDirectory = this.deps.workingDirectory
    if (workingDirectory && typeof workingDirectory.defaultDirectory === 'string' && workingDirectory.defaultDirectory) {
      return resolve(workingDirectory.defaultDirectory)
    }
    return resolve(process.cwd())
  }

  sharedLabel() {
    try {
      return basename(this.sharedRootPath()) || 'workspace'
    } catch {
      return 'workspace'
    }
  }

  isWithinRoot(root, candidate) {
    if (!candidate) return false
    if (process.platform === 'win32') return isInside(root.toLowerCase(), candidate.toLowerCase())
    return isInside(root, candidate)
  }

  relativePath(root, candidate) {
    try {
      return relative(resolve(root), resolve(candidate)).replace(/\\/g, '/')
    } catch {
      return ''
    }
  }

  audit(kind, peerId, detail) {
    this.store.state.audit.push({ time: Date.now(), kind, peerId: peerId || '', detail: String(detail || '') })
    if (this.store.state.audit.length > this.auditLimit) {
      this.store.state.audit = this.store.state.audit.slice(-this.auditLimit)
    }
  }

  emit() {
    /* Polling UI; this hook stays for future push transports. */
  }

  // -------------------------------------------------------------------------
  // Password vault and identity
  // -------------------------------------------------------------------------

  issueToken(ip) {
    const token = randomBytes(32).toString('hex')
    const expiresAt = Date.now() + TOKEN_TTL_MS
    this.tokens.set(token, { expiresAt, ip: normalizeAddress(ip) })
    return { token, expiresAt }
  }

  checkToken(token, ip) {
    const entry = this.tokens.get(String(token || ''))
    if (!entry) return false
    if (entry.expiresAt < Date.now()) {
      this.tokens.delete(String(token))
      return false
    }
    const address = normalizeAddress(ip)
    if (entry.ip && address && entry.ip !== address) return false
    entry.expiresAt = Date.now() + TOKEN_TTL_MS
    return true
  }

  dropTokens() {
    this.tokens.clear()
  }

  authGate(ip) {
    const key = normalizeAddress(ip) || 'local'
    let entry = this.authState.get(key)
    if (!entry) {
      entry = { failures: 0, windowStart: Date.now(), lockUntil: 0 }
      this.authState.set(key, entry)
    }
    return entry
  }

  async authenticate(password, ip) {
    const gate = this.authGate(ip)
    const now = Date.now()
    if (gate.lockUntil > now) {
      throw pwError('locked-out', `too many wrong passwords; retry in ${Math.ceil((gate.lockUntil - now) / 1000)}s`)
    }
    if (now - gate.windowStart > 5 * 60 * 1000) {
      gate.failures = 0
      gate.windowStart = now
    }
    try {
      await this.verifyPassword(password)
      gate.failures = 0
      return true
    } catch (error) {
      if (error && error.code === 'bad-password') {
        gate.failures += 1
        if (gate.failures >= 5) {
          gate.lockUntil = now + 30 * 1000
          gate.failures = 0
          gate.windowStart = now
        }
      }
      throw error
    }
  }

  async verifyPassword(password) {
    if (!this.store.passwordSet) throw pwError('not-configured', 'set the Peerweave password first')
    const record = this.store.state.password
    const identity = this.store.state.identity
    const master = await deriveMaster(String(password || ''), record.salt, record.params)
    try {
      const pem = openString(master, identity.sealedPrivate)
      if (!pem.includes('PRIVATE KEY')) throw new Error('invalid sealed identity')
      return pem
    } catch {
      throw pwError('bad-password', 'wrong password')
    }
  }

  assertNewPassword(password) {
    const text = String(password || '')
    if (text.length < MIN_PASSWORD) throw pwError('weak-password', `password must be at least ${MIN_PASSWORD} characters`)
    if (text.length > MAX_PASSWORD) throw pwError('weak-password', `password must be at most ${MAX_PASSWORD} characters`)
    return text
  }

  async setup(password, displayName, ip) {
    await this.ready
    if (this.store.passwordSet) throw pwError('already-configured', 'the Peerweave password is already set')
    const text = this.assertNewPassword(password)
    const identity = generateIdentity()
    const salt = randomBytes(16).toString('base64')
    const params = { N: 16384, r: 8, p: 1, keylen: 32 }
    const master = await deriveMaster(text, salt, params)
    const sealedPrivate = sealString(master, identity.privatePem)
    const fingerprintHex = fingerprint(identity.publicRaw)
    this.store.state.identity = {
      publicKey: b64(identity.publicRaw),
      sealedPrivate,
      fingerprint: fingerprintHex,
      createdAt: Date.now(),
    }
    this.store.state.password = { salt, params, createdAt: Date.now() }
    this.store.state.instanceId = this.store.state.instanceId || randomHex(16)
    if (displayName) this.store.settings.displayName = cleanName(displayName)
    if (!this.store.settings.displayName) this.store.settings.displayName = cleanName(hostname())
    await this.store.save()
    this.identity = {
      publicRaw: identity.publicRaw,
      privateKey: privateKeyFromPem(identity.privatePem),
      fingerprint: fingerprintHex,
    }
    this.audit('vault.setup', '', fingerprintHex)
    await this.store.save()
    await this.adoptRecentWorkspace()
    await this.startNetwork()
    return this.issueToken(ip)
  }

  /**
   * At setup, share the workspace of the most recent real session instead of
   * an unrelated default directory. The user can change it in Settings.
   */
  async adoptRecentWorkspace() {
    if (this.store.settings.sharedRoot) return
    const controller = this.deps.controller
    if (!controller || typeof controller.list !== 'function') return
    try {
      const list = await controller.list({}, AbortSignal.timeout(5000))
      const recent = (list.items || []).find((item) => item && item.cwd && item.blank !== true)
      if (recent && recent.cwd) {
        this.store.settings.sharedRoot = resolve(recent.cwd)
        this.audit('workspace.adopted', '', this.store.settings.sharedRoot)
        await this.store.save()
      }
    } catch {
      /* keep the configured/default root */
    }
  }

  async unlock(password, ip) {
    await this.ready
    if (!this.store.passwordSet) throw pwError('not-configured', 'set the Peerweave password first')
    const pem = await this.verifyPassword(password)
    const publicRaw = unb64u(this.store.state.identity.publicKey)
    this.identity = {
      publicRaw,
      privateKey: privateKeyFromPem(pem),
      fingerprint: this.store.state.identity.fingerprint || fingerprint(publicRaw),
    }
    await this.startNetwork()
    this.audit('vault.unlocked', '', '')
    return this.issueToken(ip)
  }

  lock() {
    this.stopAllLinks()
    this.closeAllRelayWaiters()
    this.stopReverseTunnel()
    this.stopRelayServer().catch(() => {})
    this.stopServer().catch(() => {})
    this.identity = null
    this.dropTokens()
    this.emit()
  }

  async changePassword(currentPassword, nextPassword, ip) {
    await this.authenticate(currentPassword, ip)
    const next = this.assertNewPassword(nextPassword)
    const currentPem = await this.verifyPassword(currentPassword)
    const salt = randomBytes(16).toString('base64')
    const params = { N: 16384, r: 8, p: 1, keylen: 32 }
    const master = await deriveMaster(next, salt, params)
    this.store.state.password = { salt, params, createdAt: Date.now() }
    this.store.state.identity.sealedPrivate = sealString(master, currentPem)
    await this.store.save()
    this.audit('vault.password-changed', '', '')
    return { changed: true }
  }

  async reset(password, ip) {
    await this.authenticate(password, ip)
    await this.wipeVault()
    return this.publicState()
  }

  /**
   * First step of the forgot-password escape hatch. No password is available,
   * so the only protections are loopback/same-origin fencing, an explicit
   * confirmation phrase and this server-enforced 10-second wait.
   */
  async forceResetPrepare(ip) {
    await this.ready
    const now = Date.now()
    const key = normalizeAddress(ip) || 'local'
    const nonce = randomHex(16)
    this.forceResets.set(key, { nonce, earliestAt: now + GRANT_CONFIRM_MS, expiresAt: now + 2 * 60 * 1000 })
    return { nonce, earliestAt: now + GRANT_CONFIRM_MS, delayMs: GRANT_CONFIRM_MS }
  }

  async forceResetCommit(nonce, confirm, ip) {
    await this.ready
    const key = normalizeAddress(ip) || 'local'
    const pending = this.forceResets.get(key)
    if (!pending || pending.nonce !== String(nonce || '')) {
      throw pwError('recover-expired', 'start the recovery confirmation again')
    }
    if (pending.expiresAt < Date.now()) {
      this.forceResets.delete(key)
      throw pwError('recover-expired', 'the recovery confirmation expired; start again')
    }
    if (String(confirm || '') !== 'ERASE') throw pwError('bad-request', 'the confirmation phrase is required')
    const remaining = pending.earliestAt - Date.now()
    if (remaining > 0) throw pwError('confirm-too-early', `wait ${Math.ceil(remaining / 1000)}s before confirming`)
    this.forceResets.delete(key)
    await this.wipeVault()
    return this.publicState()
  }

  async wipeVault() {
    this.stopAllLinks()
    this.closeAllRelayWaiters()
    this.stopReverseTunnel()
    await this.stopRelayServer()
    await this.stopServer()
    this.stopAuto()
    await this.archiveAllGuests()
    this.store.state = createDefaultState()
    this.store.fresh = false
    await this.store.save()
    this.store.state.audit = []
    this.identity = null
    this.dropTokens()
    this.pendingGrants.clear()
    this.forceResets.clear()
    this.emit()
  }

  // -------------------------------------------------------------------------
  // Network lifecycle
  // -------------------------------------------------------------------------

  async startNetwork() {
    if (this.disposed || !this.identity || this.server) {
      this.startAuto()
      return
    }
    const preferred = Number(this.store.settings.listenPort) || DEFAULT_PORT
    const bindHost = String(this.store.settings.bindHost || '0.0.0.0')
    let lastError = null
    for (let offset = 0; offset < 10; offset += 1) {
      const port = preferred + offset
      if (port > 65535) break
      try {
        await this.listenOn(port, bindHost)
        this.serverPort = port
        this.serverError = offset === 0 ? '' : `port ${preferred} was busy; listening on ${port}`
        this.audit('network.listening', '', String(port))
        await this.store.save()
        this.syncReverseTunnel()
        await this.startRelayServerIfEnabled()
        this.startRelayHosts()
        this.resumeRelayInvites()
        this.startAuto()
        this.emit()
        return
      } catch (error) {
        lastError = error
      }
    }
    this.serverError = `cannot listen on ${bindHost}:${preferred} (${errorText(lastError)})`
    this.log(this.serverError)
    this.startAuto()
    this.emit()
  }

  listenOn(port, bindHost) {
    return new Promise((resolvePromise, rejectPromise) => {
      const server = net.createServer((socket) => {
        this.handleInbound(socket).catch((error) => this.log('inbound failed: ' + errorText(error)))
      })
      const onError = (error) => {
        server.off('listening', onListening)
        try {
          server.close()
        } catch {
          /* ignore */
        }
        rejectPromise(error)
      }
      const onListening = () => {
        server.off('error', onError)
        server.on('error', (error) => {
          this.serverError = errorText(error)
          this.log('listener error: ' + errorText(error))
        })
        this.server = server
        resolvePromise()
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen({ port, host: bindHost, ...(bindHost === '::' ? { ipv6Only: false } : {}) })
    })
  }

  async stopServer() {
    const server = this.server
    this.server = null
    this.serverPort = 0
    if (!server) return
    await new Promise((resolvePromise) => {
      const timer = setTimeout(resolvePromise, 2000)
      timer.unref?.()
      server.close(() => {
        clearTimeout(timer)
        resolvePromise()
      })
    })
  }

  // -------------------------------------------------------------------------
  // Reverse SSH (inviter behind NAT keeps an outbound -R tunnel to a VPS)
  // -------------------------------------------------------------------------

  reverseTargetHost() {
    const target = String(this.store.settings.reverseSsh.target || '').trim()
    if (!target) return ''
    const at = target.lastIndexOf('@')
    return at >= 0 ? target.slice(at + 1) : target
  }

  reverseRunning() {
    return Boolean(this.reverseTunnel && !this.reverseTunnel.exited && !this.reverseTunnel.error)
  }

  inviteEndpoint() {
    const settings = this.store.settings
    const reverse = settings.reverseSsh
    const configuredHost = String(settings.advertiseHost || '').trim().replace(/^\[|\]$/g, '')
    if (reverse.enabled) {
      if (!this.reverseRunning()) {
        throw pwError('reverse-ssh-not-ready', 'reverse SSH is enabled but the tunnel is not running; check the target and VPS settings')
      }
      const host = configuredHost || this.reverseTargetHost()
      const port = Number(reverse.bindPort)
      if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
        throw pwError('reverse-ssh-not-ready', 'reverse SSH needs an advertised host and a valid VPS port')
      }
      return { host, port, reverse: true }
    }
    return {
      host: configuredHost || detectLanIPv4(),
      port: this.serverPort || Number(settings.listenPort) || DEFAULT_PORT,
      reverse: false,
    }
  }

  syncReverseTunnel() {
    if (this.disposed || !this.identity || !this.server) return
    const reverse = this.store.settings.reverseSsh
    if (!reverse.enabled) {
      this.stopReverseTunnel()
      return
    }
    if (this.reverseTunnel && !this.reverseTunnel.exited) return
    this.startReverseTunnel()
  }

  startReverseTunnel() {
    const reverse = this.store.settings.reverseSsh
    const target = String(reverse.target || '').trim()
    const listenPort = this.serverPort || Number(this.store.settings.listenPort) || DEFAULT_PORT
    const bindPort = Number(reverse.bindPort) || listenPort
    if (!target) {
      this.reverseError = 'reverse SSH needs a target such as user@vps.example.com'
      this.emit()
      return
    }
    const extra = String(reverse.extraArgs || '').split(/\s+/).filter(Boolean)
    const args = [
      '-N',
      '-o', 'BatchMode=yes',
      '-o', 'ExitOnForwardFailure=yes',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-R', `0.0.0.0:${bindPort}:127.0.0.1:${listenPort}`,
      ...extra,
      target,
    ]
    const child = spawn(this.sshCommand(), [...this.sshPrefixArgs(), ...args], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
    const tunnel = { child, target, bindPort, listenPort, stderr: '', exited: false, startedAt: Date.now() }
    child.stderr?.on('data', (chunk) => {
      tunnel.stderr = (tunnel.stderr + String(chunk)).slice(-4000)
    })
    child.on('error', (error) => {
      tunnel.error = errorText(error)
      tunnel.exited = true
      if (this.reverseTunnel === tunnel) {
        this.reverseTunnel = null
        this.reverseError = tunnel.error
        this.scheduleReverseRetry()
        this.emit()
      }
    })
    child.on('exit', (code, signal) => {
      tunnel.exited = true
      tunnel.exitCode = code
      tunnel.signal = signal
      if (this.reverseTunnel === tunnel) {
        this.reverseTunnel = null
        const detail = tunnel.stderr.trim().split('\n').slice(-2).join(' ')
        this.reverseError = detail || `ssh -R exited (${code ?? signal ?? 'unknown'})`
        this.log(`reverse ssh exited: ${this.reverseError}`)
        this.scheduleReverseRetry()
        this.emit()
      }
    })
    this.reverseTunnel = tunnel
    this.reverseError = ''
    this.audit('reverse-ssh.started', '', `${bindPort}->${listenPort}`)
    this.emit()
  }

  scheduleReverseRetry() {
    if (this.reverseTimer || this.disposed) return
    if (!this.store.settings.reverseSsh.enabled || !this.identity) return
    this.reverseTimer = setTimeout(() => {
      this.reverseTimer = null
      if (this.store.settings.reverseSsh.enabled && this.identity && this.server) this.startReverseTunnel()
    }, 15000)
    this.reverseTimer.unref?.()
  }

  stopReverseTunnel() {
    if (this.reverseTimer) clearTimeout(this.reverseTimer)
    this.reverseTimer = null
    const tunnel = this.reverseTunnel
    this.reverseTunnel = null
    if (!tunnel) return
    try {
      tunnel.child.kill()
    } catch {
      /* ignore */
    }
    this.reverseError = ''
  }

  // -------------------------------------------------------------------------
  // Relay server and relay host waiters
  // -------------------------------------------------------------------------

  async startRelayServerIfEnabled() {
    const config = this.store.settings.relayServer
    if (!config.enabled) {
      await this.stopRelayServer()
      return
    }
    if (this.relayServer) return
    try {
      this.relayServer = await startRelayServer({
        host: '0.0.0.0',
        port: Number(config.port) || 41338,
        token: String(config.token || ''),
        log: (message) => this.log(message),
      })
      this.relayServerError = ''
    } catch (error) {
      this.relayServerError = errorText(error)
      this.log('relay server failed: ' + this.relayServerError)
    }
    this.emit()
  }

  async stopRelayServer() {
    const server = this.relayServer
    this.relayServer = null
    if (!server) return
    try {
      await server.close()
    } catch {
      /* ignore */
    }
    this.emit()
  }

  closeRelayWaiter(waiter) {
    if (!waiter) return
    waiter.closed = true
    if (waiter.retryTimer) clearTimeout(waiter.retryTimer)
    waiter.retryTimer = null
    try {
      waiter.opened?.close()
      waiter.channel?.close()
    } catch {
      /* ignore */
    }
    this.relayWaiters.delete(waiter.relay.room)
  }

  closeAllRelayWaiters() {
    for (const waiter of [...this.relayWaiters.values()]) this.closeRelayWaiter(waiter)
  }

  startRelayHosts() {
    if (!this.identity) return
    for (const peer of this.store.peers()) {
      if (peer.transport !== 'relay' || !peer.relay || peer.relay.role !== 'host') continue
      if (!peer.autoDial || this.links.has(peer.id) || this.relayWaiters.has(peer.relay.room)) continue
      this.startRelayWaiter(peer, null)
    }
  }

  resumeRelayInvites() {
    if (!this.identity) return
    for (const invite of this.store.invites()) {
      if (!invite.relay || invite.usedAt || invite.expiresAt < Date.now()) continue
      if (this.relayWaiters.has(invite.relay.room)) continue
      this.startRelayWaiter(null, { id: invite.id, key: invite.key, relay: invite.relay })
    }
  }

  startRelayWaiter(peer, invite) {
    const relay = invite ? invite.relay : peer && peer.relay
    if (!relay) return null
    const existing = this.relayWaiters.get(relay.room)
    if (existing) return existing
    const waiter = {
      relay: normalizeRelay({ ...relay, role: 'host' }),
      peerId: peer ? peer.id : '',
      inviteId: invite ? invite.id : '',
      inviteKey: invite ? invite.key : '',
      closed: false,
      readySettled: false,
      readyResolve: null,
      readyReject: null,
      opened: null,
      channel: null,
      retryTimer: null,
      attempts: 0,
    }
    if (!waiter.relay) return null
    waiter.readyPromise = new Promise((resolvePromise, rejectPromise) => {
      waiter.readyResolve = resolvePromise
      waiter.readyReject = rejectPromise
    })
    waiter.readyPromise.catch(() => {})
    this.relayWaiters.set(waiter.relay.room, waiter)
    this.runRelayHostWaiter(waiter)
    return waiter
  }

  async runRelayHostWaiter(waiter) {
    if (waiter.closed) return
    if (!this.identity) {
      if (!waiter.readySettled) {
        waiter.readySettled = true
        waiter.readyReject?.(pwError('locked', 'unlock Peerweave before using a relay invite'))
      }
      return
    }
    try {
      const opened = await openRelay({
        host: waiter.relay.host,
        port: waiter.relay.port,
        room: waiter.relay.room,
        role: 'host',
        token: waiter.relay.token,
        waitForPeer: false,
        waitTimeoutMs: 5 * 60 * 1000,
      })
      waiter.opened = opened
      if (!waiter.readySettled) {
        waiter.readySettled = true
        waiter.readyResolve?.(waiter)
      }
      const { socket, residual } = await opened.waitForPair()
      waiter.opened = null
      if (waiter.closed) {
        socket.destroy()
        return
      }
      const channel = new SecureChannel(socket, { maxFrame: MAX_LINK_FRAME })
      waiter.channel = channel
      if (residual && residual.length > 0) channel.onData(residual)
      socket.resume()
      const result = await withTimeout(
        runResponderHandshake(channel, {
          identity: this.identity,
          name: this.displayName(),
          instanceId: this.instanceId(),
          listenPort: this.serverPort || this.store.settings.listenPort,
          lookupPeer: (raw) => this.store.peerByPublicKey(raw),
          verifyInvite: (inviteId, digestHex, proof) => this.verifyWaiterInvite(waiter, inviteId, digestHex, proof),
          tierFor: (raw) => {
            const known = this.store.peerByPublicKey(raw)
            return known ? known.tier : 0
          },
          maxFileBytes: this.store.settings.maxFileBytes,
          sharedLabel: this.sharedLabel(),
        }),
        20000,
        'relay handshake timed out',
      )
      await this.finishRelayHost(waiter, channel, result)
      waiter.channel = null
      this.relayWaiters.delete(waiter.relay.room)
    } catch (error) {
      if (!waiter.readySettled) {
        waiter.readySettled = true
        waiter.readyReject?.(error)
      }
      if (waiter.closed) return
      try {
        waiter.opened?.close()
        waiter.channel?.close()
      } catch {
        /* ignore */
      }
      waiter.opened = null
      waiter.channel = null
      this.log(`relay host room ${waiter.relay.room.slice(0, 8)}… failed: ${errorText(error)}`)
      this.scheduleRelayRetry(waiter)
    }
  }

  verifyWaiterInvite(waiter, inviteId, digestHex, proofB64) {
    if (!waiter.inviteId) return false
    if (waiter.inviteId !== inviteId) return false
    return this.verifyInvite(inviteId, digestHex, proofB64)
  }

  async finishRelayHost(waiter, channel, result) {
    const now = Date.now()
    const existing = this.store.peerByPublicKey(result.peer.publicRaw)
    const peer = this.store.upsertPeer({
      id: result.peer.fingerprint,
      publicKey: b64(result.peer.publicRaw),
      name: result.peer.name || 'DSH peer',
      instanceId: result.peer.instanceId,
      host: '',
      port: 0,
      listenPort: result.peer.listenPort || 0,
      transport: 'relay',
      relay: { ...waiter.relay, role: 'host' },
      autoDial: true,
      tier: existing ? existing.tier : 0,
      lastSeenAt: now,
    })
    if (waiter.inviteId) {
      const invite = this.store.invites().find((entry) => entry.id === waiter.inviteId)
      if (invite) invite.usedAt = now
      this.audit('peer.paired', peer.id, `relay ${waiter.relay.host}:${waiter.relay.port}`)
    } else {
      this.audit('peer.connected', peer.id, 'relay host')
    }
    await this.store.save()
    this.installLink(channel, peer, 'inbound', null, { remoteTier: -1 })
    this.emit()
  }

  scheduleRelayRetry(waiter) {
    if (waiter.retryTimer || waiter.closed) return
    let delay = 2000
    if (waiter.inviteId) {
      const invite = this.store.invites().find((entry) => entry.id === waiter.inviteId)
      if (!invite || invite.usedAt || invite.expiresAt < Date.now()) {
        this.closeRelayWaiter(waiter)
        return
      }
      delay = 1500
    } else if (waiter.peerId) {
      const peer = this.store.peer(waiter.peerId)
      if (!peer || !peer.autoDial || this.links.has(peer.id)) {
        this.closeRelayWaiter(waiter)
        return
      }
      delay = Math.min(30000, 3000 * Math.pow(2, Math.min(waiter.attempts, 3)))
    }
    waiter.attempts += 1
    waiter.retryTimer = setTimeout(() => {
      waiter.retryTimer = null
      if (!waiter.closed) this.runRelayHostWaiter(waiter)
    }, delay)
    waiter.retryTimer.unref?.()
  }

  async ensureRelayHost(peer) {
    if (this.links.get(peer.id)?.open) return this.links.get(peer.id)
    if (!peer.relay || peer.relay.role !== 'host') throw pwError('bad-request', 'this peer is not a relay host')
    if (!this.relayWaiters.has(peer.relay.room)) this.startRelayWaiter(peer, null)
    const deadline = Date.now() + 20000
    while (Date.now() < deadline) {
      const link = this.links.get(peer.id)
      if (link && link.open) return link
      await sleep(500)
    }
    throw pwError('not-connected', 'the peer has not joined the relay room yet')
  }

  async dialRelayJoin(peer, options = {}) {
    const relay = peer.relay
    const opened = await openRelay({
      host: relay.host,
      port: relay.port,
      room: relay.room,
      role: 'join',
      token: relay.token,
      waitForPeer: true,
      waitTimeoutMs: 120000,
    })
    try {
      const socket = opened.socket
      const channel = new SecureChannel(socket, { maxFrame: MAX_LINK_FRAME })
      const residual = opened.takeResidual()
      if (residual && residual.length > 0) channel.onData(residual)
      socket.resume()
      const result = await withTimeout(
        runInitiatorHandshake(channel, {
          identity: this.identity,
          name: this.displayName(),
          instanceId: this.instanceId(),
          listenPort: this.serverPort || this.store.settings.listenPort,
          expectedPeerRaw: peer.publicKey ? unb64u(peer.publicKey) : undefined,
          pair: options.pair,
        }),
        20000,
        'relay handshake timed out',
      )
      if (result.peer.fingerprint !== peer.id) {
        throw pwError('identity-mismatch', 'the peer proved a different identity than the pinned fingerprint')
      }
      const now = Date.now()
      const known = this.store.peer(peer.id)
      const updated = this.store.upsertPeer({
        id: result.peer.fingerprint,
        publicKey: b64(result.peer.publicRaw),
        name: result.peer.name || peer.name,
        instanceId: result.peer.instanceId,
        host: '',
        port: 0,
        listenPort: result.peer.listenPort || peer.listenPort,
        transport: 'relay',
        relay: { ...relay, role: 'join' },
        autoDial: true,
        tier: known ? known.tier : peer.tier,
        remoteTier: result.peer.tier,
        remoteMaxFileBytes: result.peer.maxFileBytes,
        remoteSharedLabel: result.peer.sharedLabel,
        lastSeenAt: now,
      })
      await this.store.save()
      this.dialFailures.delete(peer.id)
      this.installLink(channel, updated, 'outbound', null, {
        remoteTier: result.peer.tier,
        remoteMaxFileBytes: result.peer.maxFileBytes,
        remoteSharedLabel: result.peer.sharedLabel,
      })
      this.audit('peer.connected', peer.id, 'relay join')
      return this.links.get(peer.id)
    } catch (error) {
      opened.close()
      throw error
    }
  }

  startAuto() {
    if (this.autoTimer || this.disposed) return
    const tick = () => {
      if (!this.identity || !this.store.settings.autoConnect) return
      const now = Date.now()
      for (const peer of this.store.peers()) {
        const dialable = peer.transport === 'ssh'
          ? Boolean(peer.sshTarget)
          : peer.transport === 'relay'
            ? Boolean(peer.relay)
            : Boolean(peer.host)
        if (!peer.autoDial || !dialable || this.links.has(peer.id) || this.dialing.has(peer.id)) continue
        if (peer.transport === 'relay' && peer.relay?.role === 'host') {
          if (!this.relayWaiters.has(peer.relay.room)) this.startRelayWaiter(peer, null)
          continue
        }
        const failures = this.dialFailures.get(peer.id) || 0
        const wait = Math.min(60000, 5000 * Math.pow(2, Math.min(failures, 4)))
        const last = this.lastDialAt.get(peer.id) || 0
        if (now - last < wait) continue
        this.lastDialAt.set(peer.id, now)
        this.dial(peer).catch((error) => {
          this.dialFailures.set(peer.id, failures + 1)
          this.log(`dial ${peer.name} failed: ${errorText(error)}`)
        })
      }
    }
    this.autoTimer = setInterval(tick, 15000)
    this.autoTimer.unref?.()
    tick()
  }

  stopAuto() {
    if (this.autoTimer) clearInterval(this.autoTimer)
    this.autoTimer = null
  }

  stopAllLinks() {
    for (const link of [...this.links.values()]) {
      try {
        link.channel.close()
      } catch {
        /* ignore */
      }
    }
    this.links.clear()
    for (const tunnel of [...this.tunnels.values()]) {
      try {
        tunnel.kill()
      } catch {
        /* ignore */
      }
    }
    this.tunnels.clear()
  }

  dispose() {
    this.disposed = true
    this.stopAuto()
    this.stopAllLinks()
    this.closeAllRelayWaiters()
    this.stopReverseTunnel()
    this.stopRelayServer().catch(() => {})
    this.stopServer().catch(() => {})
    this.dropTokens()
  }

  // -------------------------------------------------------------------------
  // Inbound handshake
  // -------------------------------------------------------------------------

  async handleInbound(socket) {
    socket.setNoDelay(true)
    socket.setTimeout(30000)
    socket.once('timeout', () => socket.destroy())
    const channel = new SecureChannel(socket, { maxFrame: MAX_LINK_FRAME })
    if (!this.identity) {
      this.rejectInbound(channel, pwError('locked', 'this Peerweave instance is locked'))
      return
    }
    try {
      const result = await withTimeout(
        runResponderHandshake(channel, {
          identity: this.identity,
          name: this.displayName(),
          instanceId: this.instanceId(),
          listenPort: this.serverPort || this.store.settings.listenPort,
          lookupPeer: (raw) => this.store.peerByPublicKey(raw),
          verifyInvite: (inviteId, digestHex, proof) => this.verifyInvite(inviteId, digestHex, proof),
          tierFor: (raw) => {
            const peer = this.store.peerByPublicKey(raw)
            return peer ? peer.tier : 0
          },
          maxFileBytes: this.store.settings.maxFileBytes,
          sharedLabel: this.sharedLabel(),
        }),
        20000,
        'handshake timed out',
      )
      socket.setTimeout(0)
      await this.finishInbound(channel, result, socket)
    } catch (error) {
      this.log('inbound handshake rejected: ' + errorText(error))
      this.rejectInbound(channel, error)
    }
  }

  rejectInbound(channel, error) {
    const payload = { code: (error && error.code) || 'handshake-failed', message: errorText(error) }
    try {
      if (channel.sealed) channel.send({ t: 'error', ...payload })
      else channel.sendPlain({ t: 'pw/error', ...payload })
    } catch {
      /* ignore */
    }
    setTimeout(() => {
      try {
        channel.socket.end()
      } catch {
        /* ignore */
      }
      setTimeout(() => {
        try {
          channel.socket.destroy()
        } catch {
          /* ignore */
        }
      }, 100)
    }, 60)
  }

  async finishInbound(channel, result, socket) {
    const now = Date.now()
    const raw = result.peer.publicRaw
    let peer = this.store.peerByPublicKey(raw)
    if (!peer) {
      if (!result.pairAccepted) throw pwError('unknown-peer', 'this peer is not trusted')
      peer = this.store.upsertPeer({
        id: result.peer.fingerprint,
        publicKey: b64(raw),
        name: result.peer.name,
        instanceId: result.peer.instanceId,
        host: isLoopbackAddress(result.peer.address) ? '' : normalizeAddress(result.peer.address),
        port: result.peer.listenPort || 0,
        listenPort: result.peer.listenPort || 0,
        transport: 'tcp',
        autoDial: false,
        tier: 0,
      })
      this.audit('peer.paired', peer.id, peer.name)
    } else {
      if (result.peer.name) peer.name = cleanName(result.peer.name) || peer.name
      if (result.peer.instanceId) peer.instanceId = result.peer.instanceId
      if (result.peer.listenPort) {
        peer.listenPort = result.peer.listenPort
        if (!peer.port) peer.port = result.peer.listenPort
      }
      const address = normalizeAddress(result.peer.address)
      if (!peer.host && address && !isLoopbackAddress(address)) peer.host = address
    }
    peer.lastSeenAt = now
    if (result.pairAccepted && result.inviteId) {
      const invite = this.store.invites().find((entry) => entry.id === result.inviteId)
      if (invite) invite.usedAt = now
    }
    await this.store.save()

    const existing = this.links.get(peer.id)
    if (existing && existing.open) {
      this.rejectInbound(channel, pwError('already-connected', 'a link to this peer is already open'))
      return
    }
    this.installLink(channel, peer, 'inbound', null, { remoteTier: -1 })
    this.emit()
  }

  // -------------------------------------------------------------------------
  // Outbound connections
  // -------------------------------------------------------------------------

  async connectSocket(host, port, timeoutMs = 12000) {
    return new Promise((resolvePromise, rejectPromise) => {
      const socket = net.connect({ host, port })
      socket.setNoDelay(true)
      const timer = setTimeout(() => {
        socket.destroy()
        rejectPromise(pwError('connect-timeout', `connecting to ${host}:${port} timed out`))
      }, timeoutMs)
      timer.unref?.()
      socket.once('connect', () => {
        clearTimeout(timer)
        socket.off('error', onError)
        resolvePromise(socket)
      })
      const onError = (error) => {
        clearTimeout(timer)
        socket.destroy()
        rejectPromise(pwError('connect-failed', `${host}:${port} — ${errorText(error)}`))
      }
      socket.once('error', onError)
    })
  }

  async freeLocalPort() {
    return new Promise((resolvePromise, rejectPromise) => {
      const server = net.createServer()
      server.unref()
      server.once('error', rejectPromise)
      server.listen(0, '127.0.0.1', () => {
        const address = server.address()
        const port = address && typeof address === 'object' ? address.port : 0
        server.close(() => resolvePromise(port))
      })
    })
  }

  sshCommand() {
    return String(this.config.sshCommand || 'ssh')
  }

  sshPrefixArgs() {
    if (Array.isArray(this.config.sshPrefixArgs)) return this.config.sshPrefixArgs.map(String)
    return []
  }

  startSshTunnel(target, localPort, remotePort) {
    const extra = Array.isArray(this.config.sshExtraArgs)
      ? this.config.sshExtraArgs.map(String)
      : String(this.config.sshExtraArgs || '').split(/\s+/).filter(Boolean)
    const args = [
      '-N',
      '-o', 'BatchMode=yes',
      '-o', 'ExitOnForwardFailure=yes',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-L', `127.0.0.1:${localPort}:127.0.0.1:${remotePort}`,
      ...extra,
      String(target),
    ]
    const child = spawn(this.sshCommand(), [...this.sshPrefixArgs(), ...args], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
    const tunnel = {
      child,
      localPort,
      remotePort,
      stderr: '',
      failed: null,
      kill: () => {
        try {
          child.kill()
        } catch {
          /* ignore */
        }
      },
    }
    child.stderr?.on('data', (chunk) => {
      tunnel.stderr = (tunnel.stderr + String(chunk)).slice(-4000)
    })
    child.on('error', (error) => {
      tunnel.failed = error
    })
    child.on('exit', (code, signal) => {
      tunnel.exited = true
      tunnel.exitCode = code
      tunnel.signal = signal
    })
    this.tunnels.set(`${target}:${localPort}`, tunnel)
    return tunnel
  }

  async waitTunnel(tunnel, timeoutMs = 20000) {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      if (tunnel.failed) {
        throw pwError('ssh-failed', `cannot start ssh: ${errorText(tunnel.failed)}`)
      }
      if (tunnel.exited) {
        const detail = tunnel.stderr.trim().split('\n').slice(-2).join(' ')
        throw pwError('ssh-failed', `ssh tunnel exited (${tunnel.exitCode ?? tunnel.signal}); ${detail || 'no ssh diagnostics'}`)
      }
      try {
        const socket = await this.connectSocket('127.0.0.1', tunnel.localPort, 1200)
        socket.destroy()
        return
      } catch {
        await sleep(400)
      }
    }
    throw pwError('ssh-timeout', 'ssh tunnel did not become ready in time')
  }

  async resolveDialTarget(peer) {
    if (peer.transport === 'ssh') {
      if (!peer.sshTarget) throw pwError('no-address', 'this peer has no ssh target')
      const remotePort = Number(peer.sshRemotePort) || Number(peer.listenPort) || DEFAULT_PORT
      const localPort = await this.freeLocalPort()
      const tunnel = this.startSshTunnel(peer.sshTarget, localPort, remotePort)
      await this.waitTunnel(tunnel)
      return { host: '127.0.0.1', port: localPort, tunnel }
    }
    if (!peer.host) throw pwError('no-address', 'this peer has no address yet')
    return { host: peer.host, port: Number(peer.port) || Number(peer.listenPort) || DEFAULT_PORT, tunnel: null }
  }

  async dial(peerOrId, options = {}) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave with the install password first')
    const peer = typeof peerOrId === 'string' ? this.store.peer(peerOrId) : peerOrId
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    const existing = this.links.get(peer.id)
    if (existing && existing.open) return existing
    if (peer.transport === 'relay') {
      if (!peer.relay) throw pwError('no-address', 'this relay peer has no relay settings')
      if (peer.relay.role === 'host') return this.ensureRelayHost(peer)
      if (this.dialing.has(peer.id)) throw pwError('busy', 'a connection attempt is already running')
      this.dialing.add(peer.id)
      try {
        return await this.dialRelayJoin(peer, options)
      } finally {
        this.dialing.delete(peer.id)
      }
    }
    if (this.dialing.has(peer.id)) throw pwError('busy', 'a connection attempt is already running')
    this.dialing.add(peer.id)
    let tunnel = null
    try {
      const target = await this.resolveDialTarget(peer)
      tunnel = target.tunnel
      const socket = await this.connectSocket(target.host, target.port)
      const channel = new SecureChannel(socket, { maxFrame: MAX_LINK_FRAME })
      const result = await withTimeout(
        runInitiatorHandshake(channel, {
          identity: this.identity,
          name: this.displayName(),
          instanceId: this.instanceId(),
          listenPort: this.serverPort || this.store.settings.listenPort,
          expectedPeerRaw: peer.publicKey ? unb64u(peer.publicKey) : undefined,
          pair: options.pair,
        }),
        20000,
        'handshake timed out',
      )
      if (result.peer.fingerprint !== peer.id) {
        throw pwError('identity-mismatch', 'the peer proved a different identity than the pinned fingerprint')
      }
      const now = Date.now()
      const known = this.store.peer(peer.id)
      const updated = this.store.upsertPeer({
        id: result.peer.fingerprint,
        publicKey: b64(result.peer.publicRaw),
        name: result.peer.name || peer.name,
        instanceId: result.peer.instanceId,
        host: peer.host || '',
        port: peer.transport === 'tcp' ? Number(peer.port) || target.port : Number(peer.port) || 0,
        listenPort: result.peer.listenPort || peer.listenPort,
        transport: peer.transport,
        sshTarget: peer.sshTarget,
        sshRemotePort: peer.sshRemotePort,
        autoDial: peer.autoDial,
        tier: known ? known.tier : peer.tier,
        remoteTier: result.peer.tier,
        remoteMaxFileBytes: result.peer.maxFileBytes,
        remoteSharedLabel: result.peer.sharedLabel,
        lastSeenAt: now,
      })
      await this.store.save()
      this.dialFailures.delete(peer.id)
      this.installLink(channel, updated, 'outbound', tunnel, {
        remoteTier: result.peer.tier,
        remoteMaxFileBytes: result.peer.maxFileBytes,
        remoteSharedLabel: result.peer.sharedLabel,
      })
      this.audit('peer.connected', peer.id, 'outbound')
      return this.links.get(peer.id)
    } catch (error) {
      if (tunnel) {
        tunnel.kill()
        for (const [key, entry] of this.tunnels) {
          if (entry === tunnel) this.tunnels.delete(key)
        }
      }
      throw error
    } finally {
      this.dialing.delete(peer.id)
    }
  }

  installLink(channel, peer, direction, tunnel, meta = {}) {
    const link = {
      peerId: peer.id,
      channel,
      direction,
      tunnel,
      remoteTier: typeof meta.remoteTier === 'number' ? meta.remoteTier : -1,
      remoteMaxFileBytes: meta.remoteMaxFileBytes || 0,
      remoteSharedLabel: meta.remoteSharedLabel || '',
      openedAt: Date.now(),
      lastSeen: Date.now(),
      pending: new Map(),
      seq: 0,
      opTimes: [],
      chatTimes: [],
      pingTimer: null,
      open: true,
    }
    channel.onFrame((message) => this.onLinkFrame(link, message))
    channel.onClose((error) => this.onLinkClosed(link, error))
    link.pingTimer = setInterval(() => {
      if (Date.now() - link.lastSeen > 90000) {
        channel.close()
        return
      }
      try {
        channel.send({ t: 'ping' })
      } catch {
        channel.close()
      }
    }, 20000)
    link.pingTimer.unref?.()
    this.links.set(peer.id, link)
    const queued = channel.plainQueue.splice(0)
    for (const message of queued) this.onLinkFrame(link, message)
    this.emit()
    this.refreshPeerInfo(link).catch(() => {})
    return link
  }

  onLinkClosed(link, error) {
    if (!link.open) return
    link.open = false
    if (link.pingTimer) clearInterval(link.pingTimer)
    for (const pending of link.pending.values()) {
      clearTimeout(pending.timer)
      pending.reject(pwError('disconnected', 'peer disconnected'))
    }
    link.pending.clear()
    if (this.links.get(link.peerId) === link) this.links.delete(link.peerId)
    if (link.tunnel) {
      try {
        link.tunnel.kill()
      } catch {
        /* ignore */
      }
      for (const [key, tunnel] of this.tunnels) {
        if (tunnel === link.tunnel) this.tunnels.delete(key)
      }
    }
    this.log(`link ${link.peerId.slice(0, 8)} closed: ${errorText(error)}`)
    const peer = this.store.peer(link.peerId)
    if (peer && peer.transport === 'relay' && peer.relay && peer.relay.role === 'host' && peer.autoDial && !this.disposed) {
      const timer = setTimeout(() => this.startRelayHosts(), 1500)
      timer.unref?.()
    }
    this.emit()
  }

  onLinkFrame(link, message) {
    if (!link.open || !message || typeof message !== 'object') return
    link.lastSeen = Date.now()
    switch (message.t) {
      case 'ping':
        try {
          link.channel.send({ t: 'pong' })
        } catch {
          /* ignore */
        }
        return
      case 'pong':
        return
      case 'res': {
        const pending = link.pending.get(message.id)
        if (!pending) return
        link.pending.delete(message.id)
        clearTimeout(pending.timer)
        if (message.ok) pending.resolve(message.value)
        else pending.reject(pwError((message.error && message.error.code) || 'remote-error', (message.error && message.error.message) || 'remote error'))
        return
      }
      case 'req':
        this.handleLinkRequest(link, message).catch((error) => this.log('request failed: ' + errorText(error)))
        return
      case 'evt':
        this.handleLinkEvent(link, message)
        return
      case 'error':
        link.channel.close()
        return
      default:
        return
    }
  }

  handleLinkEvent(link, message) {
    if (message.topic !== 'grant') return
    const peer = this.store.peer(link.peerId)
    if (!peer) return
    const data = message.data || {}
    peer.remoteTier = Number.isInteger(data.tier) ? data.tier : peer.remoteTier
    peer.remoteMaxFileBytes = Number(data.maxFileBytes) || peer.remoteMaxFileBytes
    peer.remoteSharedLabel = String(data.sharedLabel || peer.remoteSharedLabel || '')
    link.remoteTier = peer.remoteTier
    this.store.save().catch(() => {})
    this.emit()
  }

  async handleLinkRequest(link, message) {
    const id = message.id
    try {
      const value = await this.dispatchRemote(link, String(message.op || ''), message.args && typeof message.args === 'object' ? message.args : {})
      link.channel.send({ t: 'res', id, ok: true, value })
    } catch (error) {
      link.channel.send({
        t: 'res',
        id,
        ok: false,
        error: { code: (error && error.code) || 'error', message: errorText(error) },
      })
    }
  }

  async dispatchRemote(link, op, args) {
    const now = Date.now()
    link.opTimes = link.opTimes.filter((time) => now - time < 60000)
    if (op === 'files.readChunk') {
      // Chunked transfers need a higher request rate than interactive calls.
      link.chunkTimes = (link.chunkTimes || []).filter((time) => now - time < 60000)
      if (link.chunkTimes.length >= 180) throw pwError('rate-limited', 'too many transfer chunks; slow down')
      link.chunkTimes.push(now)
    } else {
      if (link.opTimes.length >= 90) throw pwError('rate-limited', 'too many requests; slow down')
      link.opTimes.push(now)
    }
    const peer = this.store.peer(link.peerId)
    if (!peer) throw pwError('unknown-peer', 'this peer is no longer trusted')
    const tier = peer.tier
    const requireTier = (minimum) => {
      if (tier < minimum) {
        throw pwError(
          'permission-denied',
          `the local owner grants tier ${tier} (${TIER_NAMES[tier] || 'linked'}); this operation needs tier ${minimum} (${TIER_NAMES[minimum]})`,
        )
      }
    }
    switch (op) {
      case 'info':
        return this.ownInfo(peer)
      case 'history.list':
        requireTier(1)
        return this.listHistory()
      case 'history.read':
        requireTier(1)
        return this.readHistory(String(args.sessionId || ''))
      case 'files.workspaces':
        requireTier(2)
        return this.fileWorkspaces()
      case 'files.list':
        requireTier(2)
        return this.listFiles(String(args.path || ''), args.workspaceId ? String(args.workspaceId) : '')
      case 'files.stat':
        requireTier(2)
        return this.statSharedFile(String(args.path || ''), args.workspaceId ? String(args.workspaceId) : '')
      case 'files.read':
        requireTier(2)
        return this.readSharedFile(String(args.path || ''), args.workspaceId ? String(args.workspaceId) : '')
      case 'files.readChunk':
        requireTier(2)
        return this.readSharedFileChunk(
          String(args.path || ''),
          args.offset,
          args.length,
          args.workspaceId ? String(args.workspaceId) : '',
        )
      case 'chat.send':
        requireTier(3)
        return this.chatAsGuest(link, args)
      default:
        throw pwError('unknown-op', `unknown operation: ${op}`)
    }
  }

  ownInfo(peer) {
    return {
      name: this.displayName(),
      instanceId: this.instanceId(),
      fingerprint: this.identity ? this.identity.fingerprint : '',
      yourTier: peer.tier,
      maxFileBytes: this.store.settings.maxFileBytes,
      sharedLabel: this.sharedLabel(),
      platform: process.platform,
      version: VERSION,
      time: Date.now(),
    }
  }

  requestOp(link, op, args, timeoutMs = LINK_TIMEOUT) {
    return new Promise((resolvePromise, rejectPromise) => {
      if (!link.open) {
        rejectPromise(pwError('not-connected', 'peer is not connected'))
        return
      }
      const id = `${++link.seq}-${randomHex(4)}`
      const timer = setTimeout(() => {
        link.pending.delete(id)
        rejectPromise(pwError('timeout', `${op} timed out`))
      }, timeoutMs)
      timer.unref?.()
      link.pending.set(id, { resolve: resolvePromise, reject: rejectPromise, timer })
      try {
        link.channel.send({ t: 'req', id, op, args })
      } catch (error) {
        clearTimeout(timer)
        link.pending.delete(id)
        rejectPromise(pwError('send-failed', errorText(error)))
      }
    })
  }

  async refreshPeerInfo(link) {
    const info = await this.requestOp(link, 'info', {}, 8000)
    const peer = this.store.peer(link.peerId)
    if (!peer) return
    if (Number.isInteger(info.yourTier)) peer.remoteTier = info.yourTier
    if (Number(info.maxFileBytes)) peer.remoteMaxFileBytes = Number(info.maxFileBytes)
    if (info.sharedLabel) peer.remoteSharedLabel = String(info.sharedLabel)
    if (info.name) peer.name = cleanName(info.name) || peer.name
    link.remoteTier = peer.remoteTier
    link.remoteMaxFileBytes = peer.remoteMaxFileBytes
    link.remoteSharedLabel = peer.remoteSharedLabel
    await this.store.save()
    this.emit()
  }

  async ensureLink(peerId) {
    const peer = this.store.peer(peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    const link = this.links.get(peerId)
    if (link && link.open) return link
    await this.dial(peer)
    const fresh = this.links.get(peerId)
    if (!fresh || !fresh.open) throw pwError('not-connected', 'peer is not connected')
    return fresh
  }

  async remoteCall(peerId, op, args, timeoutMs) {
    const link = await this.ensureLink(peerId)
    return this.requestOp(link, op, args, timeoutMs)
  }

  // -------------------------------------------------------------------------
  // Invites and trust
  // -------------------------------------------------------------------------

  parseInviteCode(code) {
    const text = String(code || '').trim()
    if (!text.startsWith('PW1-')) throw pwError('bad-invite', 'invite codes start with PW1-')
    let payload
    try {
      payload = JSON.parse(unb64u(text.slice(4)).toString('utf8'))
    } catch {
      throw pwError('bad-invite', 'invite code is malformed')
    }
    if (!payload || payload.v !== 1) throw pwError('bad-invite', 'unsupported invite version')
    if (typeof payload.host !== 'string' || !payload.host) throw pwError('bad-invite', 'invite has no host')
    if (!Number.isInteger(payload.port) || payload.port <= 0 || payload.port > 65535) throw pwError('bad-invite', 'invite has no port')
    if (typeof payload.fp !== 'string' || !/^[0-9a-f]{64}$/i.test(payload.fp)) throw pwError('bad-invite', 'invite has no identity fingerprint')
    if (typeof payload.key !== 'string' || unb64u(payload.key).length !== 32) throw pwError('bad-invite', 'invite has no pairing secret')
    if (Number(payload.expiresAt) < Date.now()) throw pwError('invite-expired', 'this invite code has expired')
    if (payload.relay !== undefined) {
      const relay = payload.relay
      if (!relay || typeof relay !== 'object') throw pwError('bad-invite', 'invite relay settings are malformed')
      if (typeof relay.host !== 'string' || !relay.host.trim()) throw pwError('bad-invite', 'invite relay has no host')
      if (!Number.isInteger(relay.port) || relay.port <= 0 || relay.port > 65535) throw pwError('bad-invite', 'invite relay has no port')
      if (typeof relay.room !== 'string' || !/^[a-f0-9]{16,64}$/i.test(relay.room)) throw pwError('bad-invite', 'invite relay has no room')
      if (relay.token !== undefined && typeof relay.token !== 'string') throw pwError('bad-invite', 'invite relay token is malformed')
    }
    return payload
  }

  async createInvite(password, ip, options = {}) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    await this.authenticate(password, ip)
    const mode = options && options.mode === 'relay' ? 'relay' : 'direct'
    const id = randomHex(8)
    const key = randomBytes(32)
    const expiresAt = Date.now() + 10 * 60 * 1000
    let host
    let port
    let relay = null
    if (mode === 'relay') {
      const config = this.store.settings.relayClient
      const relayHost = String(config.host || '').trim()
      const relayPort = Number(config.port) || 41338
      if (!relayHost) throw pwError('relay-not-configured', 'set a relay host in the cross-network settings first')
      relay = {
        host: relayHost,
        port: relayPort,
        room: randomHex(16),
        token: String(config.token || ''),
        role: 'host',
      }
      host = relayHost
      port = relayPort
    } else {
      if (!this.server) await this.startNetwork()
      if (!this.server) throw pwError('not-listening', this.serverError || 'Peerweave cannot listen; check the port settings')
      const endpoint = this.inviteEndpoint()
      host = endpoint.host
      port = endpoint.port
    }
    const payload = {
      v: 1,
      host,
      port,
      fp: this.identity.fingerprint,
      name: this.displayName(),
      instance: this.instanceId(),
      id,
      key: b64u(key),
      expiresAt,
    }
    if (relay) payload.relay = { host: relay.host, port: relay.port, room: relay.room, token: relay.token }
    this.store.state.invites.push({ id, key: b64u(key), expiresAt, createdAt: Date.now(), usedAt: 0, relay })
    this.store.state.invites = this.store.state.invites.filter((invite) => invite.expiresAt > Date.now() - 24 * 60 * 60 * 1000)
    await this.store.save()

    if (relay) {
      const waiter = this.startRelayWaiter(null, { id, key, relay })
      try {
        await waiter.readyPromise
      } catch (error) {
        this.closeRelayWaiter(waiter)
        this.store.state.invites = this.store.state.invites.filter((invite) => invite.id !== id)
        await this.store.save()
        throw error
      }
    }

    this.audit('invite.created', '', `${mode} ${id}`)
    return {
      code: `PW1-${b64u(JSON.stringify(payload))}`,
      host,
      port,
      mode,
      relay: relay ? { host: relay.host, port: relay.port } : null,
      expiresAt,
      fingerprint: shortFingerprint(this.identity.fingerprint),
    }
  }

  verifyInvite(inviteId, digestHex, proofB64) {
    const invite = this.store.invites().find((entry) => entry.id === inviteId)
    if (!invite || invite.usedAt || invite.expiresAt < Date.now()) return false
    let proof
    try {
      proof = unb64u(proofB64)
    } catch {
      return false
    }
    const expected = hmacSha256(unb64u(invite.key), digestHex)
    return timingSafeEq(expected, proof)
  }

  async acceptInvite({ code, transport, sshTarget, sshRemotePort, dialHost, dialPort }, ip) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    const invite = this.parseInviteCode(code)
    if (invite.relay) {
      const relay = {
        host: String(invite.relay.host),
        port: Number(invite.relay.port) || 41338,
        room: String(invite.relay.room).toLowerCase(),
        token: String(invite.relay.token || ''),
        role: 'join',
      }
      const stub = {
        id: invite.fp.toLowerCase(),
        publicKey: '',
        name: cleanName(invite.name) || 'DSH peer',
        host: '',
        port: 0,
        listenPort: invite.port,
        transport: 'relay',
        relay,
        autoDial: true,
        tier: 0,
      }
      const link = await this.dial(stub, { pair: { id: invite.id, key: unb64u(invite.key) } })
      const peer = this.store.peer(link.peerId)
      this.audit('peer.joined', link.peerId, `relay ${relay.host}:${relay.port}`)
      return { peer: peer ? this.peerView(peer) : null }
    }
    const mode = transport === 'ssh' ? 'ssh' : 'tcp'
    const host = String(dialHost || '').trim() || invite.host
    const requestedPort = Number(dialPort) || invite.port
    if (!Number.isInteger(requestedPort) || requestedPort <= 0 || requestedPort > 65535) {
      throw pwError('bad-request', 'the dial port must be 1-65535')
    }
    const stub = {
      id: invite.fp.toLowerCase(),
      publicKey: '',
      name: cleanName(invite.name) || 'DSH peer',
      host: mode === 'ssh' ? '' : host,
      port: mode === 'ssh' ? 0 : requestedPort,
      listenPort: invite.port,
      transport: mode,
      sshTarget: mode === 'ssh' ? String(sshTarget || '').trim() : '',
      sshRemotePort: mode === 'ssh' ? Number(sshRemotePort) || requestedPort : 0,
      autoDial: true,
      tier: 0,
    }
    if (mode === 'ssh' && !stub.sshTarget) throw pwError('bad-request', 'ssh transport needs an ssh target such as user@host')
    const link = await this.dial(stub, { pair: { id: invite.id, key: unb64u(invite.key) } })
    const peer = this.store.peer(link.peerId)
    this.audit('peer.joined', link.peerId, `${stub.transport} ${host}:${requestedPort}`)
    return { peer: peer ? this.peerView(peer) : null }
  }

  // -------------------------------------------------------------------------
  // Local peer management
  // -------------------------------------------------------------------------

  async connectPeer(peerId) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    const peer = this.store.peer(peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    await this.dial(peer)
    return this.peerView(peer)
  }

  disconnectPeer(peerId) {
    const link = this.links.get(peerId)
    if (link) link.channel.close()
    return { disconnected: true }
  }

  async removePeer(peerId, password, ip) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    await this.authenticate(password, ip)
    const peer = this.store.peer(peerId)
    const link = this.links.get(peerId)
    if (link) link.channel.close()
    for (const waiter of [...this.relayWaiters.values()]) {
      if (waiter.peerId === peerId) this.closeRelayWaiter(waiter)
    }
    await this.archiveGuest(peer)
    const removed = this.store.removePeer(peerId)
    if (!removed) throw pwError('unknown-peer', 'unknown peer')
    await this.store.save()
    this.audit('peer.removed', peerId, '')
    return { removed: true }
  }

  async archiveGuest(peer) {
    const registry = this.deps.registry
    if (!peer || !peer.guestSessionId || !registry || typeof registry.archiveSession !== 'function') return
    try {
      await registry.archiveSession(peer.guestSessionId)
    } catch {
      /* the session may already be gone */
    }
  }

  async archiveAllGuests() {
    for (const peer of this.store.peers()) await this.archiveGuest(peer)
  }

  async prepareGrant(peerId, tier, password, ip) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    await this.authenticate(password, ip)
    const peer = this.store.peer(peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    const nextTier = Number(tier)
    if (!Number.isInteger(nextTier) || nextTier < 0 || nextTier > 3) throw pwError('bad-tier', 'tier must be 0, 1, 2 or 3')
    const now = Date.now()
    const needsDelay = nextTier === 3 && peer.tier !== 3
    const nonce = randomHex(16)
    const earliestAt = now + (needsDelay ? GRANT_CONFIRM_MS : 0)
    const entry = { nonce, peerId, tier: nextTier, earliestAt, expiresAt: now + 2 * 60 * 1000 }
    this.pendingGrants.set(nonce, entry)
    this.audit('grant.prepared', peerId, `${peer.tier}->${nextTier}`)
    return {
      nonce,
      tier: nextTier,
      currentTier: peer.tier,
      earliestAt,
      delayMs: Math.max(0, earliestAt - now),
      warning: needsDelay,
    }
  }

  async commitGrant(peerId, tier, nonce, password, ip) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    await this.authenticate(password, ip)
    const peer = this.store.peer(peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    const entry = this.pendingGrants.get(String(nonce || ''))
    if (!entry) throw pwError('grant-expired', 'start the permission change again')
    if (entry.peerId !== peerId || entry.tier !== Number(tier)) throw pwError('grant-mismatch', 'permission change does not match the prepared request')
    if (entry.expiresAt < Date.now()) {
      this.pendingGrants.delete(entry.nonce)
      throw pwError('grant-expired', 'permission change timed out; start again')
    }
    const remaining = entry.earliestAt - Date.now()
    if (remaining > 0) {
      throw pwError('confirm-too-early', `wait ${Math.ceil(remaining / 1000)}s before confirming tier 3`)
    }
    this.pendingGrants.delete(entry.nonce)
    const from = peer.tier
    peer.tier = Number(tier)
    await this.store.save()
    this.audit('grant.changed', peerId, `${from}->${peer.tier}`)
    this.notifyGrant(peer)
    this.emit()
    return { peer: this.peerView(peer), from }
  }

  notifyGrant(peer) {
    const link = this.links.get(peer.id)
    if (!link || !link.open) return
    try {
      link.channel.send({
        t: 'evt',
        topic: 'grant',
        data: { tier: peer.tier, maxFileBytes: this.store.settings.maxFileBytes, sharedLabel: this.sharedLabel() },
      })
    } catch {
      /* ignore */
    }
  }

  async updateSettings(patch, password, ip) {
    await this.ready
    if (!this.identity) throw pwError('locked', 'unlock Peerweave first')
    await this.authenticate(password, ip)
    const changes = {}
    const settings = this.store.settings
    if (Object.prototype.hasOwnProperty.call(patch, 'maxFileBytes')) {
      settings.maxFileBytes = clampBytes(patch.maxFileBytes)
      changes.maxFileBytes = settings.maxFileBytes
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'autoConnect')) {
      settings.autoConnect = Boolean(patch.autoConnect)
      changes.autoConnect = settings.autoConnect
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'displayName')) {
      settings.displayName = cleanName(patch.displayName) || cleanName(hostname())
      changes.displayName = settings.displayName
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'advertiseHost')) {
      settings.advertiseHost = String(patch.advertiseHost || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\[|\]$/g, '')
      changes.advertiseHost = settings.advertiseHost
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'sharedRoot')) {
      const value = String(patch.sharedRoot || '').trim()
      if (value) {
        const abs = resolve(value)
        const info = await stat(abs).catch(() => null)
        if (!info || !info.isDirectory()) throw pwError('bad-path', 'shared root must be an existing directory')
        settings.sharedRoot = abs
      } else {
        settings.sharedRoot = ''
      }
      changes.sharedRoot = this.sharedRootPath()
    }
    let restart = false
    let reverseChanged = false
    let relayServerChanged = false
    if (Object.prototype.hasOwnProperty.call(patch, 'listenPort')) {
      const port = Number(patch.listenPort)
      if (!Number.isInteger(port) || port < 1024 || port > 65535) throw pwError('bad-port', 'listen port must be 1024-65535')
      if (port !== settings.listenPort) {
        settings.listenPort = port
        changes.listenPort = port
        restart = true
      }
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'bindHost')) {
      const bindHost = String(patch.bindHost || '0.0.0.0')
      if (bindHost !== '0.0.0.0' && bindHost !== '::') throw pwError('bad-bind', 'bindHost must be 0.0.0.0 or ::')
      if (bindHost !== settings.bindHost) {
        settings.bindHost = bindHost
        changes.bindHost = bindHost
        restart = true
      }
    }
    if (patch.reverseSsh && typeof patch.reverseSsh === 'object') {
      const next = { ...settings.reverseSsh, ...patch.reverseSsh }
      next.enabled = Boolean(next.enabled)
      next.target = String(next.target || '').trim()
      next.bindPort = Number(next.bindPort) || 0
      next.extraArgs = String(next.extraArgs || '')
      if (next.enabled) {
        if (!next.target) throw pwError('bad-request', 'reverse SSH needs a target such as user@vps')
        if (!Number.isInteger(next.bindPort) || next.bindPort < 1024 || next.bindPort > 65535) {
          throw pwError('bad-port', 'the VPS bind port must be 1024-65535')
        }
      }
      settings.reverseSsh = next
      changes.reverseSsh = true
      reverseChanged = true
    }
    if (patch.relayServer && typeof patch.relayServer === 'object') {
      const next = { ...settings.relayServer, ...patch.relayServer }
      next.enabled = Boolean(next.enabled)
      next.port = Number(next.port) || 41338
      next.token = String(next.token || '')
      if (!Number.isInteger(next.port) || next.port < 1024 || next.port > 65535) throw pwError('bad-port', 'relay port must be 1024-65535')
      if (/\s/.test(next.token)) throw pwError('bad-request', 'the relay token must not contain whitespace')
      settings.relayServer = next
      changes.relayServer = true
      relayServerChanged = true
    }
    if (patch.relayClient && typeof patch.relayClient === 'object') {
      const next = { ...settings.relayClient, ...patch.relayClient }
      next.host = String(next.host || '').trim().replace(/^\[|\]$/g, '')
      next.port = Number(next.port) || 41338
      next.token = String(next.token || '')
      if (!Number.isInteger(next.port) || next.port < 1 || next.port > 65535) throw pwError('bad-port', 'relay port must be 1-65535')
      if (/\s/.test(next.token)) throw pwError('bad-request', 'the relay token must not contain whitespace')
      settings.relayClient = next
      changes.relayClient = true
    }
    await this.store.save()
    this.audit('settings.updated', '', Object.keys(changes).join(','))
    if (changingBytes(changes)) {
      for (const peer of this.store.peers()) this.notifyGrant(peer)
    }
    if (restart) {
      this.stopAllLinks()
      this.closeAllRelayWaiters()
      this.stopReverseTunnel()
      await this.stopServer()
      await this.startNetwork()
    } else if (reverseChanged) {
      this.stopReverseTunnel()
      this.syncReverseTunnel()
    }
    if (relayServerChanged) {
      await this.stopRelayServer()
      await this.startRelayServerIfEnabled()
    }
    if (changes.relayClient) {
      this.audit('relay-client.updated', '', `${settings.relayClient.host}:${settings.relayClient.port}`)
    }
    return this.publicState()
  }

  fullSettings() {
    return JSON.parse(JSON.stringify(this.store.settings))
  }

  // -------------------------------------------------------------------------
  // History
  // -------------------------------------------------------------------------

  workspaceCatalog() {
    const registry = this.deps.registry
    if (!registry || typeof registry.list !== 'function') return []
    try {
      return registry.list().map((workspace) => ({
        id: String(workspace.id),
        title: String(workspace.title || basename(String(workspace.path)) || 'Workspace'),
        path: String(workspace.path),
      }))
    } catch {
      return []
    }
  }

  normalizedPath(value) {
    try {
      const resolved = resolve(String(value))
      return process.platform === 'win32' ? resolved.toLowerCase() : resolved
    } catch {
      return String(value)
    }
  }

  workspaceForSession(summary, catalog) {
    const cwd = String((summary && summary.cwd) || '')
    if (!cwd) return null
    let best = null
    for (const workspace of catalog) {
      if (this.isWithinRoot(workspace.path, cwd)) {
        if (!best || workspace.path.length > best.path.length) best = workspace
      }
    }
    return best
  }

  async listHistory() {
    const controller = this.deps.controller
    if (!controller) throw pwError('unavailable', 'the session service is unavailable')
    const list = await controller.list({}, AbortSignal.timeout(10000))
    const items = list.items.filter((summary) => summary.blank !== true).slice(0, 200)
    const titles = new Map()
    const query = this.deps.query
    if (query && items.length > 0) {
      try {
        const observations = await query.readTitleSnapshots(items.map((summary) => summary.sessionId), AbortSignal.timeout(10000))
        for (const observation of observations) {
          if (observation && observation.status === 'fulfilled' && observation.value && observation.value.title) {
            titles.set(observation.sessionId, observation.value.title.title)
          }
        }
      } catch {
        /* titles are optional */
      }
    }
    const catalog = this.workspaceCatalog()
    const groups = new Map()
    for (const workspace of catalog) {
      groups.set(workspace.id, { id: workspace.id, title: workspace.title, path: workspace.path, sessions: [] })
    }
    const viewOf = (summary, workspace) => ({
      id: summary.sessionId,
      title: titles.get(summary.sessionId) || `Session ${String(summary.sessionId).slice(-6)}`,
      updatedAt: summary.updatedAt || 0,
      running: Boolean(summary.running),
      path: summary.cwd || '',
      workspaceId: workspace ? workspace.id : '',
      workspaceTitle: workspace ? workspace.title : (summary.cwd ? basename(summary.cwd) : 'Other sessions'),
    })
    const flat = []
    for (const summary of items) {
      const workspace = this.workspaceForSession(summary, catalog)
      const view = viewOf(summary, workspace)
      flat.push(view)
      const key = workspace ? workspace.id : `cwd:${this.normalizedPath(summary.cwd || '')}`
      if (!groups.has(key)) {
        groups.set(key, {
          id: key,
          title: view.workspaceTitle,
          path: summary.cwd || '',
          sessions: [],
        })
      }
      groups.get(key).sessions.push(view)
    }
    const workspaces = [...groups.values()]
      .map((group) => ({
        ...group,
        sessions: group.sessions.sort((left, right) => right.updatedAt - left.updatedAt),
      }))
      .sort((left, right) => {
        const leftIndex = catalog.findIndex((workspace) => workspace.id === left.id)
        const rightIndex = catalog.findIndex((workspace) => workspace.id === right.id)
        if (leftIndex >= 0 && rightIndex >= 0) return leftIndex - rightIndex
        if (leftIndex >= 0) return -1
        if (rightIndex >= 0) return 1
        return left.title.localeCompare(right.title)
      })
    return {
      workspace: this.sharedLabel(),
      rootLabel: this.sharedLabel(),
      workspaces,
      sessions: flat.sort((left, right) => right.updatedAt - left.updatedAt),
    }
  }

  async readHistory(sessionId) {
    if (typeof sessionId !== 'string' || !sessionId) throw pwError('bad-request', 'sessionId is required')
    const controller = this.deps.controller
    if (!controller) throw pwError('unavailable', 'the session service is unavailable')
    const list = await controller.list({}, AbortSignal.timeout(10000))
    const summary = list.items.find((entry) => entry.sessionId === sessionId)
    if (!summary) throw pwError('session-not-shared', 'that session is not available')
    const workspace = this.workspaceForSession(summary, this.workspaceCatalog())
    let title = ''
    const query = this.deps.query
    if (query) {
      try {
        const snapshot = await query.readTitle(sessionId, AbortSignal.timeout(8000))
        if (snapshot && snapshot.title) title = snapshot.title
      } catch {
        /* optional */
      }
    }
    const page = await controller.events(
      { address: { kind: 'session', sessionId }, maxMessages: 100 },
      AbortSignal.timeout(20000),
    )
    const messages = []
    let budget = 150000
    for (const record of page.records || []) {
      const event = record && record.event ? record.event : record
      const mapped = mapWireEvent(event)
      if (!mapped || !mapped.text) continue
      const text = mapped.text.length > 8000 ? `${mapped.text.slice(0, 8000)}\n…[truncated]` : mapped.text
      if (budget - text.length < 0) break
      budget -= text.length
      messages.push({ ...mapped, text })
    }
    return {
      sessionId,
      title,
      path: summary.cwd || '',
      workspaceId: workspace ? workspace.id : '',
      workspaceTitle: workspace ? workspace.title : '',
      messages,
      hasMore: Boolean(page.hasMore),
    }
  }

  // -------------------------------------------------------------------------
  // Shared files (read-only, size-capped)
  // -------------------------------------------------------------------------

  fileLimit() {
    return Math.min(clampBytes(this.store.settings.maxFileBytes), MAX_FILE_HARD_LIMIT)
  }

  async fileWorkspaces() {
    const catalog = this.workspaceCatalog()
    if (catalog.length > 0) return { workspaces: catalog }
    return {
      workspaces: [{ id: 'shared', title: this.sharedLabel(), path: this.sharedRootPath() }],
    }
  }

  async resolveWorkspaceRoot(workspaceId) {
    if (!workspaceId) return this.sharedRootPath()
    const catalog = this.workspaceCatalog()
    const workspace = catalog.find((entry) => entry.id === workspaceId)
    if (workspace) return workspace.path
    if (workspaceId === 'shared') return this.sharedRootPath()
    throw pwError('unknown-workspace', 'unknown workspace')
  }

  async listFiles(relInput, workspaceId) {
    const root = await this.resolveWorkspaceRoot(workspaceId)
    const { realRoot, abs, rel } = await safeResolveInside(root, relInput)
    let info
    try {
      info = await stat(abs)
    } catch {
      throw pwError('not-found', 'directory not found')
    }
    if (!info.isDirectory()) throw pwError('not-a-directory', 'not a directory')
    const dirents = await readdir(abs, { withFileTypes: true })
    const entries = []
    for (const dirent of dirents.slice(0, 500)) {
      const childAbs = join(abs, dirent.name)
      const childRel = rel ? `${rel}/${dirent.name}` : dirent.name
      let type = dirent.isDirectory() ? 'dir' : dirent.isFile() ? 'file' : 'link'
      let size = null
      let mtimeMs = null
      let safe = true
      try {
        const real = await realpath(childAbs)
        if (!isInside(realRoot, real)) {
          safe = false
          type = 'link'
        } else if (type === 'link') {
          const linked = await stat(real)
          type = linked.isDirectory() ? 'dir' : linked.isFile() ? 'file' : 'link'
        }
        if (type === 'file') {
          const fileInfo = await stat(childAbs)
          size = fileInfo.size
          mtimeMs = fileInfo.mtimeMs
        }
      } catch {
        safe = false
        type = 'link'
      }
      entries.push({ name: dirent.name, type, size, mtimeMs, path: childRel, safe })
    }
    entries.sort((left, right) => {
      if (left.type !== right.type) {
        if (left.type === 'dir') return -1
        if (right.type === 'dir') return 1
      }
      return left.name.localeCompare(right.name)
    })
    return {
      workspace: this.sharedLabel(),
      path: rel,
      parent: rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '',
      entries,
      limitBytes: this.fileLimit(),
      truncated: dirents.length > 500,
    }
  }

  async statSharedFile(relInput, workspaceId) {
    const root = await this.resolveWorkspaceRoot(workspaceId)
    const result = await statSafe(root, relInput)
    if (!result.exists) throw pwError('not-found', 'file not found')
    if (!result.info.isFile()) throw pwError('not-a-file', 'not a regular file')
    return {
      path: result.rel,
      bytes: result.info.size,
      mtimeMs: result.info.mtimeMs,
      readable: result.info.size <= this.fileLimit(),
      limitBytes: this.fileLimit(),
    }
  }

  async readSharedFile(relInput, workspaceId) {
    const root = await this.resolveWorkspaceRoot(workspaceId)
    const result = await statSafe(root, relInput)
    if (!result.exists) throw pwError('not-found', 'file not found')
    if (!result.info.isFile()) throw pwError('not-a-file', 'not a regular file')
    const limit = this.fileLimit()
    if (result.info.size > limit) {
      throw pwError('file-too-large', `file is ${result.info.size} bytes; the sharing limit is ${limit} bytes`)
    }
    if (result.info.size > MAX_INLINE_READ_BYTES) {
      throw pwError(
        'file-needs-transfer',
        `file is ${result.info.size} bytes; inline reads stop at ${MAX_INLINE_READ_BYTES} bytes. Copy it to the reader's workspace to transfer it.`,
      )
    }
    const buffer = await readFile(result.abs)
    const binary = isBinaryBuffer(buffer)
    return {
      path: result.rel,
      bytes: buffer.length,
      mtimeMs: result.info.mtimeMs,
      encoding: binary ? 'base64' : 'utf8',
      text: binary ? undefined : buffer.toString('utf8'),
      data: binary ? buffer.toString('base64') : undefined,
    }
  }

  async readSharedFileChunk(relInput, offsetInput, lengthInput, workspaceId) {
    const offset = Number(offsetInput)
    const requested = Number(lengthInput)
    if (!Number.isInteger(offset) || offset < 0) throw pwError('bad-request', 'offset must be a non-negative integer')
    if (!Number.isInteger(requested) || requested <= 0) throw pwError('bad-request', 'length must be a positive integer')
    const length = Math.min(requested, FILE_CHUNK_BYTES)
    const root = await this.resolveWorkspaceRoot(workspaceId)
    const result = await statSafe(root, relInput)
    if (!result.exists) throw pwError('not-found', 'file not found')
    if (!result.info.isFile()) throw pwError('not-a-file', 'not a regular file')
    const total = result.info.size
    const limit = this.fileLimit()
    if (total > limit) throw pwError('file-too-large', `file is ${total} bytes; the sharing limit is ${limit} bytes`)
    if (offset > total) throw pwError('bad-request', 'offset is beyond the end of the file')
    if (offset === total) {
      return { path: result.rel, offset, bytes: 0, totalBytes: total, eof: true, data: '' }
    }
    const want = Math.min(length, total - offset)
    const handle = await open(result.abs, 'r')
    try {
      const buffer = Buffer.allocUnsafe(want)
      const { bytesRead } = await handle.read(buffer, 0, want, offset)
      return {
        path: result.rel,
        offset,
        bytes: bytesRead,
        totalBytes: total,
        eof: offset + bytesRead >= total,
        data: buffer.subarray(0, bytesRead).toString('base64'),
      }
    } finally {
      await handle.close()
    }
  }

  async copyFromPeer(peerId, remotePath, workspaceId) {
    const peer = this.store.peer(peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    let rel
    try {
      rel = normalizeRelative(remotePath)
    } catch (error) {
      throw pwError('bad-path', errorText(error))
    }
    if (!rel) throw pwError('bad-path', 'choose a file, not the workspace root')

    // Stat first so an oversized file is refused before anything is written.
    const info = await this.remoteCall(peerId, 'files.stat', { path: rel, workspaceId }, 20000)
    if (!info.readable) {
      throw pwError('file-too-large', `file is ${info.bytes} bytes; the peer's sharing limit is ${info.limitBytes} bytes`)
    }
    if (info.bytes > MAX_FILE_HARD_LIMIT) throw pwError('file-too-large', 'file exceeds the local hard limit')

    const root = join(this.sharedRootPath(), 'peerweave-imports', sanitizeSegment(peer.name))
    const target = resolve(root, rel)
    if (!isInside(root, target)) throw pwError('bad-path', 'path escapes the import directory')
    await mkdir(dirname(target), { recursive: true })

    const handle = await open(target, 'w')
    let offset = 0
    let totalBytes = 0
    try {
      for (;;) {
        const chunk = await this.remoteCall(
          peerId,
          'files.readChunk',
          { path: rel, offset, length: FILE_CHUNK_BYTES, workspaceId },
          60000,
        )
        const buffer = Buffer.from(String(chunk.data || ''), 'base64')
        if (buffer.length > 0) {
          let written = 0
          while (written < buffer.length) {
            const { bytesWritten } = await handle.write(buffer, written, buffer.length - written)
            if (!bytesWritten) throw pwError('transfer-failed', 'the local disk accepted no bytes')
            written += bytesWritten
          }
        }
        totalBytes += buffer.length
        if (totalBytes > MAX_FILE_HARD_LIMIT) throw pwError('file-too-large', 'file exceeds the local hard limit')
        if (chunk.eof) break
        if (buffer.length === 0) throw pwError('transfer-failed', 'peer returned an empty chunk before the end of the file')
        offset += buffer.length
      }
    } catch (error) {
      await handle.close().catch(() => {})
      await rm(target, { force: true }).catch(() => {})
      throw error
    }
    await handle.close()
    if (Number.isFinite(info.bytes) && totalBytes !== info.bytes) {
      throw pwError('transfer-incomplete', `received ${totalBytes} of ${info.bytes} bytes`)
    }
    this.audit('file.copied', peerId, `${rel} (${totalBytes} bytes)`)
    await this.store.save()
    return { localPath: target, bytes: totalBytes, path: rel }
  }

  // -------------------------------------------------------------------------
  // Chat with the local DSH on behalf of a tier-3 peer
  // -------------------------------------------------------------------------

  withGuestChain(peerId, fn) {
    const previous = this.chatChains.get(peerId) || Promise.resolve()
    const next = previous.then(fn, fn)
    this.chatChains.set(peerId, next.catch(() => {}))
    return next
  }

  async ensureGuest(peer) {
    const controller = this.deps.controller
    if (!controller) throw pwError('unavailable', 'the session service is unavailable')
    if (peer.guestSessionId) return peer.guestSessionId
    const created = await controller.create({ cwd: this.sharedRootPath() })
    peer.guestSessionId = created.sessionId
    await this.store.save()
    try {
      await controller.rename({ sessionId: created.sessionId, title: `Peerweave guest · ${peer.name}` })
    } catch {
      /* title is cosmetic */
    }
    this.audit('guest.created', peer.id, created.sessionId)
    await this.store.save()
    return created.sessionId
  }

  async runGuestPrompt(controller, guestId, text, started) {
    let cursor = 0
    try {
      const state = await controller.state({ sessionId: guestId })
      cursor = Number(state.cursor) || 0
    } catch {
      /* a cold session still accepts a prompt */
    }
    const requestId = `peerweave-${randomHex(8)}`
    await controller.prompt(
      { requestId, sessionId: guestId, mode: 'queue', content: [{ type: 'text', text }] },
      AbortSignal.timeout(20000),
    )
    let result = null
    try {
      result = await controller.wait(
        { sessionId: guestId, timeoutMs: 90000, afterSeq: cursor, maxMessages: 40 },
        AbortSignal.timeout(110000),
      )
    } catch (error) {
      throw pwError('chat-failed', `the local DSH could not finish: ${errorText(error)}`)
    }
    const records = (result && result.output && result.output.records) || []
    const parts = []
    for (const record of records) {
      const event = record && record.event ? record.event : record
      if (!event || event.type !== 'assistant/message') continue
      const message = event.data && event.data.message
      const textPart = blocksText(message && message.content)
      if (textPart) parts.push(textPart)
    }
    let reply = parts.join('\n\n').trim()
    const reason = (result && result.reason) || 'unknown'
    let note = ''
    if (reason === 'timeout') note = 'The local DSH is still working; the answer was cut off by the sharing timeout.'
    if (reason === 'input-required') note = 'The local DSH is waiting for its owner to answer an approval or a question.'
    if (!reply) reply = note || 'The local DSH produced no text answer.'
    else if (note) reply = `${reply}\n\n(${note})`
    return { reply, sessionId: guestId, reason, elapsedMs: Date.now() - started, truncated: reply.length > 100000 }
  }

  async chatAsGuest(link, args) {
    const text = String(args.text == null ? '' : args.text)
    if (!text.trim()) throw pwError('empty-message', 'message text is required')
    if (text.length > 4000) throw pwError('message-too-long', 'messages are limited to 4000 characters')
    const now = Date.now()
    link.chatTimes = link.chatTimes.filter((time) => now - time < 60000)
    if (link.chatTimes.length >= 4) throw pwError('rate-limited', 'chat is limited to 4 messages per minute')
    link.chatTimes.push(now)
    const peer = this.store.peer(link.peerId)
    if (!peer) throw pwError('unknown-peer', 'unknown peer')
    return this.withGuestChain(peer.id, async () => {
      const started = Date.now()
      const controller = this.deps.controller
      if (!controller) throw pwError('unavailable', 'the session service is unavailable')
      let guestId = await this.ensureGuest(peer)
      try {
        return await this.runGuestPrompt(controller, guestId, text, started)
      } catch (error) {
        if (error && (error.code === 'chat-failed' || error.code === 'session/not-found') && /not.?found/i.test(errorText(error))) {
          peer.guestSessionId = ''
          await this.store.save()
          guestId = await this.ensureGuest(peer)
          return this.runGuestPrompt(controller, guestId, text, started)
        }
        throw error
      }
    })
  }

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------

  peerView(peer) {
    const link = this.links.get(peer.id)
    const connected = Boolean(link && link.open)
    return {
      id: peer.id,
      name: peer.name,
      fingerprint: shortFingerprint(peer.id),
      fingerprintFull: peer.id,
      tier: peer.tier,
      tierName: TIER_NAMES[peer.tier] || 'linked',
      remoteTier: peer.remoteTier,
      remoteTierName: peer.remoteTier >= 0 ? TIER_NAMES[peer.remoteTier] || 'linked' : 'unknown',
      connected,
      direction: connected ? link.direction : null,
      host: peer.host,
      port: peer.port,
      listenPort: peer.listenPort,
      transport: peer.transport,
      sshTarget: peer.sshTarget,
      relay: peer.relay ? { host: peer.relay.host, port: peer.relay.port, role: peer.relay.role } : null,
      endpoint: peer.transport === 'relay'
        ? `relay ${peer.relay ? `${peer.relay.host}:${peer.relay.port}` : '?'}`
        : peer.transport === 'ssh'
          ? `ssh ${peer.sshTarget}:${peer.sshRemotePort || peer.listenPort}`
          : `${peer.host || '?'}:${peer.port || peer.listenPort || '?'}`,
      lastSeenAt: peer.lastSeenAt,
      addedAt: peer.addedAt,
      remoteSharedLabel: peer.remoteSharedLabel,
      remoteMaxFileBytes: peer.remoteMaxFileBytes,
      guest: Boolean(peer.guestSessionId),
    }
  }

  publicState() {
    if (!this.store.state) {
      return { ok: false, error: { code: 'loading', message: 'Peerweave is starting' } }
    }
    const identity = this.store.state.identity
    const settings = this.store.settings
    return {
      ok: true,
      version: VERSION,
      name: this.displayName(),
      instanceId: this.store.state.instanceId || '',
      passwordSet: this.store.passwordSet,
      unlocked: Boolean(this.identity),
      locked: !this.identity,
      fingerprint: identity ? shortFingerprint(identity.fingerprint) : '',
      fingerprintFull: identity ? identity.fingerprint : '',
      listening: {
        active: Boolean(this.server),
        port: this.serverPort || Number(settings.listenPort),
        bindHost: settings.bindHost || '0.0.0.0',
        advertisedHost: settings.advertiseHost || detectLanIPv4(),
      },
      serverError: this.serverError,
      reverseSsh: {
        enabled: Boolean(settings.reverseSsh.enabled),
        running: this.reverseRunning(),
        target: settings.reverseSsh.target || '',
        bindPort: Number(settings.reverseSsh.bindPort) || 0,
        error: this.reverseError,
      },
      relayServer: {
        enabled: Boolean(settings.relayServer.enabled),
        running: Boolean(this.relayServer),
        port: Number(settings.relayServer.port) || 41338,
        error: this.relayServerError,
      },
      relayClient: {
        host: settings.relayClient.host || '',
        port: Number(settings.relayClient.port) || 41338,
        tokenSet: Boolean(settings.relayClient.token),
      },
      settings: {
        maxFileBytes: clampBytes(settings.maxFileBytes),
        listenPort: Number(settings.listenPort),
        bindHost: settings.bindHost || '0.0.0.0',
        autoConnect: Boolean(settings.autoConnect),
        sharedRoot: this.identity ? this.sharedRootPath() : '',
        sharedLabel: this.sharedLabel(),
        displayName: this.displayName(),
        advertiseHost: settings.advertiseHost || '',
      },
      peers: this.store.peers().map((peer) => this.peerView(peer)),
      activeInvites: this.store.invites().filter((invite) => !invite.usedAt && invite.expiresAt > Date.now()).length,
      audit: (this.store.state.audit || []).slice(-30).reverse(),
      now: Date.now(),
    }
  }
}

function changingBytes(changes) {
  return Object.prototype.hasOwnProperty.call(changes, 'maxFileBytes')
}

export { GRANT_CONFIRM_MS }
