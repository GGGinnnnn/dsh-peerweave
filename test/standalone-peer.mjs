/**
 * Stand-alone Peerweave peer used by the end-to-end test.
 *
 * It speaks the real protocol and lets the test drive it over stdin:
 *   node test/standalone-peer.mjs --state <dir> --join <invite-code>
 *   node test/standalone-peer.mjs --state <dir> --listen 41338
 *
 * stdout carries one JSON object per line; stdin accepts one JSON command per
 * line. It implements a few fixture responses so the Peerweave host's outgoing
 * operations (history/files/copy) can be exercised too.
 */
import net from 'node:net'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import readline from 'node:readline'
import { randomBytes } from 'node:crypto'
import { SecureChannel, runInitiatorHandshake, runResponderHandshake } from '../lib/protocol.js'
import {
  b64,
  b64u,
  fingerprint,
  generateIdentity,
  hmacSha256,
  privateKeyFromPem,
  randomHex,
  shortFingerprint,
  timingSafeEq,
  unb64u,
} from '../lib/util.js'

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i]
    if (!item.startsWith('--')) continue
    const key = item.slice(2)
    const next = argv[i + 1]
    if (next && !next.startsWith('--')) {
      out[key] = next
      i += 1
    } else {
      out[key] = true
    }
  }
  return out
}

const args = parseArgs(process.argv.slice(2))
const stateDir = args.state || join(process.cwd(), 'test', '.peer-state')
const displayName = args.name || 'Standalone DSH'
const instanceId = `standalone-${randomHex(4)}`
const log = (value) => process.stdout.write(`${JSON.stringify(value)}\n`)

await mkdir(stateDir, { recursive: true })

async function loadIdentity() {
  const file = join(stateDir, 'identity.json')
  try {
    const raw = JSON.parse(await readFile(file, 'utf8'))
    return { publicRaw: unb64u(raw.publicKey), privatePem: raw.privatePem }
  } catch {
    const identity = generateIdentity()
    await writeFile(file, JSON.stringify({ publicKey: b64(identity.publicRaw), privatePem: identity.privatePem }, null, 2), { mode: 0o600 })
    return identity
  }
}

const identity = await loadIdentity()
const identityKey = privateKeyFromPem(identity.privatePem)
const myFingerprint = fingerprint(identity.publicRaw)
let peerTier = 0 // the access this stand-in grants to the Peerweave host
let remoteTier = -1 // the access the host grants to this stand-in
let rpc = null
let channel = null
let server = null
const invite = { id: null, key: null }

function fixtureInfo() {
  return {
    name: displayName,
    instanceId,
    fingerprint: myFingerprint,
    yourTier: peerTier,
    maxFileBytes: 1048576,
    sharedLabel: 'standalone-ws',
    platform: process.platform,
    version: '1.0.0',
    time: Date.now(),
  }
}

async function handleRequest(op, requestArgs) {
  switch (op) {
    case 'info':
      return fixtureInfo()
    case 'history.list':
      return {
        workspace: 'standalone-ws',
        sessions: [
          { id: 'session-standalone-1', title: 'Stand-in transcript', updatedAt: Date.now(), running: false, path: '' },
        ],
      }
    case 'history.read':
      return {
        sessionId: String(requestArgs.sessionId || ''),
        title: 'Stand-in transcript',
        path: '',
        messages: [
          { role: 'user', seq: 1, time: Date.now(), text: 'hello from the stand-in peer' },
          { role: 'assistant', seq: 2, time: Date.now(), text: 'stand-in assistant reply' },
        ],
        hasMore: false,
      }
    case 'files.list':
      return {
        workspace: 'standalone-ws',
        path: String(requestArgs.path || ''),
        parent: '',
        entries: [
          { name: 'notes', type: 'dir', size: null, mtimeMs: null, path: 'notes', safe: true },
          { name: 'standin.txt', type: 'file', size: 42, mtimeMs: Date.now(), path: 'standin.txt', safe: true },
        ],
        limitBytes: 1048576,
        truncated: false,
      }
    case 'files.read':
      return {
        path: String(requestArgs.path || 'standin.txt'),
        bytes: 42,
        mtimeMs: Date.now(),
        encoding: 'utf8',
        text: 'file served by the stand-in peer (read-only)',
      }
    case 'files.stat':
      return { path: String(requestArgs.path || ''), bytes: 42, mtimeMs: Date.now(), readable: true, limitBytes: 1048576 }
    case 'chat.send':
      return { reply: `stand-in DSH received: ${String(requestArgs.text || '')}`, sessionId: 'session-standalone-1', reason: 'completed', elapsedMs: 1, truncated: false }
    default: {
      const error = new Error(`stand-in has no operation ${op}`)
      error.code = 'unknown-op'
      throw error
    }
  }
}

class Rpc {
  constructor(secure) {
    this.channel = secure
    this.pending = new Map()
    this.seq = 0
    secure.onFrame((message) => this.onFrame(message))
    secure.onClose((error) => {
      log({ event: 'closed', message: String((error && error.message) || '') })
      setTimeout(() => process.exit(0), 20)
    })
  }

  async onFrame(message) {
    if (!message || typeof message !== 'object') return
    if (message.t === 'ping') {
      this.channel.send({ t: 'pong' })
      return
    }
    if (message.t === 'pong') return
    if (message.t === 'res') {
      const pending = this.pending.get(message.id)
      if (!pending) return
      this.pending.delete(message.id)
      clearTimeout(pending.timer)
      if (message.ok) pending.resolve(message.value)
      else {
        const error = new Error((message.error && message.error.message) || 'remote error')
        error.code = (message.error && message.error.code) || 'remote-error'
        pending.reject(error)
      }
      return
    }
    if (message.t === 'evt') {
      if (message.topic === 'grant') {
        remoteTier = Number(message.data && message.data.tier)
        log({ event: 'grant', tier: remoteTier })
      }
      return
    }
    if (message.t === 'req') {
      try {
        const value = await handleRequest(String(message.op || ''), message.args || {})
        this.channel.send({ t: 'res', id: message.id, ok: true, value })
      } catch (error) {
        this.channel.send({ t: 'res', id: message.id, ok: false, error: { code: error.code || 'error', message: error.message } })
      }
    }
  }

  request(op, requestArgs, timeoutMs = 20000) {
    return new Promise((resolvePromise, rejectPromise) => {
      const id = `${++this.seq}-${randomHex(3)}`
      const timer = setTimeout(() => {
        this.pending.delete(id)
        rejectPromise(Object.assign(new Error(`${op} timed out`), { code: 'timeout' }))
      }, timeoutMs)
      this.pending.set(id, { resolve: resolvePromise, reject: rejectPromise, timer })
      this.channel.send({ t: 'req', id, op, args: requestArgs || {} })
    })
  }

  sendGrant(tier) {
    this.channel.send({ t: 'evt', topic: 'grant', data: { tier, maxFileBytes: 1048576, sharedLabel: 'standalone-ws' } })
  }
}

function connect(host, port) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = net.connect({ host, port, timeout: 10000 })
    socket.once('connect', () => resolvePromise(socket))
    socket.once('timeout', () => rejectPromise(new Error('connect timeout')))
    socket.once('error', rejectPromise)
  })
}

async function startJoin(code) {
  const inviteText = String(code)
  if (!inviteText.startsWith('PW1-')) throw new Error('bad invite code')
  const payload = JSON.parse(unb64u(inviteText.slice(4)).toString('utf8'))
  const socket = await connect(payload.host, payload.port)
  channel = new SecureChannel(socket)
  const result = await runInitiatorHandshake(channel, {
    identity: { publicRaw: identity.publicRaw, privateKey: identityKey },
    name: displayName,
    instanceId,
    listenPort: 0,
    pair: { id: payload.id, key: unb64u(payload.key) },
  })
  if (result.peer.fingerprint !== String(payload.fp).toLowerCase()) throw new Error('inviter fingerprint mismatch')
  remoteTier = result.peer.tier
  rpc = new Rpc(channel)
  log({ event: 'connected', mode: 'join', peer: result.peer.name, host: payload.host, port: payload.port, fingerprint: shortFingerprint(myFingerprint), remoteTier })
}

async function startHost(port) {
  invite.key = randomBytes(32)
  invite.id = randomHex(8)
  server = net.createServer(async (socket) => {
    try {
      channel = new SecureChannel(socket)
      const result = await runResponderHandshake(channel, {
        identity: { publicRaw: identity.publicRaw, privateKey: identityKey },
        name: displayName,
        instanceId,
        listenPort: server.address().port,
        lookupPeer: () => undefined,
        verifyInvite: (id, digest, proof) => id === invite.id && timingSafeEq(hmacSha256(invite.key, digest), unb64u(proof)),
        tierFor: () => 0,
        maxFileBytes: 1048576,
        sharedLabel: 'standalone-ws',
      })
      rpc = new Rpc(channel)
      remoteTier = result.peer.tier
      log({ event: 'connected', mode: 'host', peer: result.peer.name, fingerprint: shortFingerprint(myFingerprint), remoteTier })
    } catch (error) {
      log({ event: 'error', message: error.message, code: error.code })
    }
  })
  await new Promise((resolvePromise) => server.listen(port, '127.0.0.1', resolvePromise))
  const actual = server.address().port
  const payload = {
    v: 1,
    host: '127.0.0.1',
    port: actual,
    fp: myFingerprint,
    name: displayName,
    instance: instanceId,
    id: invite.id,
    key: b64u(invite.key),
    expiresAt: Date.now() + 10 * 60 * 1000,
  }
  log({ event: 'invite', code: `PW1-${b64u(JSON.stringify(payload))}`, port: actual })
}

if (args.join) {
  await startJoin(args.join)
} else if (args.listen) {
  await startHost(Number(args.listen))
} else {
  throw new Error('use --join <code> or --listen <port>')
}

const input = readline.createInterface({ input: process.stdin })
input.on('line', async (line) => {
  const text = String(line).trim()
  if (!text) return
  let command
  try {
    command = JSON.parse(text)
  } catch {
    log({ event: 'error', message: 'command must be JSON' })
    return
  }
  const id = command.id || null
  try {
    if (command.op === 'close') {
      channel?.close()
      server?.close()
      process.exit(0)
    }
    if (command.op === 'grantState') {
      log({ event: 'result', id, ok: true, value: { remoteTier, peerTier } })
      return
    }
    if (command.op === 'setGrantToPeer') {
      peerTier = Number(command.tier)
      rpc.sendGrant(peerTier)
      log({ event: 'result', id, ok: true, value: { peerTier } })
      return
    }
    const value = await rpc.request(command.op, command.args || {}, Number(command.timeoutMs) || 20000)
    log({ event: 'result', id, ok: true, value })
  } catch (error) {
    log({ event: 'result', id, ok: false, error: { code: error.code || 'error', message: error.message } })
  }
})
