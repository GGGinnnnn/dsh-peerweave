/**
 * End-to-end test of the installed Peerweave plugin against a stand-in peer.
 *
 * It covers: first-run password setup, invite pairing, tier gating (0..3),
 * history reads, file reads and the size cap, copying a peer file into the
 * local workspace, the enforced 10-second tier-3 delay, chat through the local
 * DSH agent, outgoing dialing, and the password/token checks.
 *
 * Run with: node test/e2e.mjs
 */
import { spawn } from 'node:child_process'
import { readFile, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import readline from 'node:readline'

const HERE = dirname(fileURLToPath(import.meta.url))
const PEER_SCRIPT = join(HERE, 'standalone-peer.mjs')
const BASE = process.env.PEERWEAVE_BASE || 'http://127.0.0.1:13310'
const PASSWORD = 'Peerweave-E2E-2026!'
const TMP = join(HERE, '.e2e')
const IMPORTS = join(dirname(HERE), 'peerweave-imports')
let token = null

function log(message) {
  process.stdout.write(`\n== ${message}\n`)
}

async function http(action, body, options = {}) {
  const headers = { 'x-peerweave': '1' }
  if (!options.noToken && token) headers['x-peerweave-token'] = token
  if (body !== undefined) headers['content-type'] = 'application/json'
  const response = await fetch(`${BASE}/peerweave/${action}`, {
    method: options.method || (body === undefined ? 'GET' : 'POST'),
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => null)
  if (!payload) throw new Error(`${action}: HTTP ${response.status}`)
  if (!payload.ok) {
    const error = new Error(payload.error && payload.error.message)
    error.code = payload.error && payload.error.code
    error.status = response.status
    throw error
  }
  return payload.data === undefined ? payload : payload.data
}

async function waitUntil(label, fn, timeoutMs = 15000, intervalMs = 300) {
  const deadline = Date.now() + timeoutMs
  let last
  while (Date.now() < deadline) {
    try {
      const value = await fn()
      if (value) return value
      last = value
    } catch (error) {
      last = error
    }
    await new Promise((done) => setTimeout(done, intervalMs))
  }
  throw new Error(`${label} did not settle: ${last instanceof Error ? last.message : JSON.stringify(last)}`)
}

class PeerProcess {
  constructor(args) {
    this.child = spawn(process.execPath, [PEER_SCRIPT, ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
    this.events = []
    this.waiters = []
    this.stderr = ''
    this.seq = 0
    this.closed = false
    readline.createInterface({ input: this.child.stdout }).on('line', (line) => {
      let event
      try {
        event = JSON.parse(line)
      } catch {
        return
      }
      if (event.event === 'closed') this.closed = true
      this.events.push(event)
      for (const waiter of [...this.waiters]) {
        if (waiter.match(event)) {
          this.waiters.splice(this.waiters.indexOf(waiter), 1)
          clearTimeout(waiter.timer)
          waiter.resolve(event)
        }
      }
    })
    this.child.stderr.on('data', (chunk) => {
      this.stderr += String(chunk)
    })
    this.child.on('exit', () => {
      this.closed = true
    })
  }

  waitFor(match, timeoutMs = 15000) {
    const existing = this.events.find(match)
    if (existing) {
      this.events.splice(this.events.indexOf(existing), 1)
      return Promise.resolve(existing)
    }
    return new Promise((resolvePromise, rejectPromise) => {
      const waiter = {
        match,
        resolve: resolvePromise,
        timer: setTimeout(() => {
          this.waiters.splice(this.waiters.indexOf(waiter), 1)
          rejectPromise(new Error(`event timed out; stderr=${this.stderr.slice(-800)}`))
        }, timeoutMs),
      }
      this.waiters.push(waiter)
    })
  }

  send(command) {
    this.child.stdin.write(`${JSON.stringify(command)}\n`)
  }

  async call(op, args = {}, timeoutMs = 30000) {
    const id = `c${++this.seq}`
    this.send({ op, args, id })
    const event = await this.waitFor((entry) => entry.event === 'result' && entry.id === id, timeoutMs)
    if (!event.ok) {
      const error = new Error(event.error.message)
      error.code = event.error.code
      throw error
    }
    return event.value
  }

  async close() {
    try {
      this.send({ op: 'close' })
    } catch {
      /* ignore */
    }
    setTimeout(() => {
      try {
        this.child.kill()
      } catch {
        /* ignore */
      }
    }, 500)
  }
}

async function deny(label, promise, code) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.code, code, `${label}: expected ${code}, got ${error.code}: ${error.message}`)
    log(`${label}: denied with ${code}`)
    return
  }
  throw new Error(`${label}: expected ${code}, but the call succeeded`)
}

async function tierChange(peerId, tier, delayCommit = false) {
  const prepared = await http('permission/prepare', { peerId, tier, password: PASSWORD })
  if (delayCommit) {
    await new Promise((done) => setTimeout(done, Math.max(0, prepared.earliestAt - Date.now()) + 700))
  }
  return http('permission/commit', { peerId, tier, nonce: prepared.nonce, password: PASSWORD })
}

let peerB = null
let exitCode = 0
let runningPeerA = null

try {
  log('read public state')
  let state = await http('public', undefined, { noToken: true })
  if (state.passwordSet) {
    log('vault exists; unlocking with the test password')
    const unlocked = await http('unlock', { password: PASSWORD }, { noToken: true })
    token = unlocked.token
  } else {
    log('create the install password')
    const created = await http('setup', { password: PASSWORD, confirm: PASSWORD, displayName: 'Peerweave E2E host' }, { noToken: true })
    token = created.token
    state = await http('public', undefined, { noToken: true })
  }
  assert.equal(state.unlocked, true)
  assert.equal(state.passwordSet, true)
  assert.ok(state.fingerprint.startsWith('PW-'))
  await waitUntil('listener', async () => {
    const next = await http('public', undefined, { noToken: true })
    return next.listening.active ? next : null
  })
  log(`identity ${state.fingerprint}, listening ${state.listening.port}`)

  const invite = await http('invite/create', { password: PASSWORD })
  assert.ok(invite.code.startsWith('PW1-'))
  log(`invite created for ${invite.host}:${invite.port}`)

  runningPeerA = new PeerProcess(['--state', join(TMP, 'peer-a'), '--join', invite.code, '--name', 'Standalone A'])
  const peerAConnected = runningPeerA
  const connectedA = await peerAConnected.waitFor((event) => event.event === 'connected', 20000)
  log(`peer A connected as ${connectedA.fingerprint}`)

  const peerIdA = await waitUntil('peer A in public state', async () => {
    const next = await http('public', undefined, { noToken: true })
    return next.peers.find((peer) => peer.name === 'Standalone A' && peer.connected) || null
  })
  log(`peer id ${peerIdA.id.slice(0, 16)}…`)

  const info = await peerAConnected.call('info')
  assert.equal(info.yourTier, 0)
  log('tier 0: info allowed')

  await deny('tier 0 history', peerAConnected.call('history.list'), 'permission-denied')
  await deny('tier 0 files', peerAConnected.call('files.list', { path: '' }), 'permission-denied')

  log('grant tier 1 (history)')
  const grant1 = await tierChange(peerIdA.id, 1)
  assert.equal(grant1.peer.tier, 1)
  await waitUntil('peer A sees tier 1', () => peerAConnected.waitFor((event) => event.event === 'grant' && event.tier === 1, 5000))

  const history = await peerAConnected.call('history.list')
  assert.ok(Array.isArray(history.sessions) && history.sessions.length > 0, 'expected sessions in the shared workspace')
  const sessionId = history.sessions[0].id
  const transcript = await peerAConnected.call('history.read', { sessionId })
  assert.ok(Array.isArray(transcript.messages))
  assert.ok(transcript.messages.length > 0, 'expected transcript messages')
  log(`history okay: ${history.sessions.length} sessions, ${transcript.messages.length} messages in ${sessionId.slice(0, 20)}…`)

  await deny('tier 1 files', peerAConnected.call('files.list', { path: '' }), 'permission-denied')

  log('grant tier 2 (files)')
  const grant2 = await tierChange(peerIdA.id, 2)
  assert.equal(grant2.peer.tier, 2)
  await waitUntil('peer A sees tier 2', () => peerAConnected.waitFor((event) => event.event === 'grant' && event.tier === 2, 5000))

  const root = await peerAConnected.call('files.list', { path: '' })
  assert.ok(root.entries.some((entry) => entry.name === 'dsh-peerweave'))
  const pkg = await peerAConnected.call('files.read', { path: 'dsh-peerweave/package.json' })
  assert.ok(pkg.text.includes('dsh-peerweave'), 'expected package.json content')
  log(`files okay: ${root.entries.length} root entries, package.json ${pkg.bytes} bytes`)

  log('apply a 1 KiB sharing limit')
  await http('settings/update', { password: PASSWORD, patch: { maxFileBytes: 1024 } })
  await deny('size cap', peerAConnected.call('files.read', { path: 'dsh-peerweave/client.js' }), 'file-too-large')
  await http('settings/update', { password: PASSWORD, patch: { maxFileBytes: 2 * 1024 * 1024 } })
  log('size cap restored')

  log('peer grants this machine tier 2; copy a peer file into the workspace')
  await peerAConnected.send({ op: 'setGrantToPeer', tier: 2 })
  await waitUntil('remote tier 2', async () => {
    const next = await http('public', undefined, { noToken: true })
    const peer = next.peers.find((entry) => entry.id === peerIdA.id)
    return peer && peer.remoteTier === 2 ? peer : null
  })
  const remoteHistory = await http('remote/history/list', { peerId: peerIdA.id })
  assert.equal(remoteHistory.sessions[0].title, 'Stand-in transcript')
  const remoteFile = await http('remote/files/read', { peerId: peerIdA.id, path: 'standin.txt' })
  assert.ok(remoteFile.text.includes('stand-in peer'))
  const copied = await http('remote/copy', { peerId: peerIdA.id, path: 'standin.txt' })
  const copiedText = await readFile(copied.localPath, 'utf8')
  assert.ok(copiedText.includes('stand-in peer'))
  log(`remote ops okay; copied to ${copied.localPath}`)

  log('tier 3 needs the 10-second confirmation')
  const prepared = await http('permission/prepare', { peerId: peerIdA.id, tier: 3, password: PASSWORD })
  assert.equal(prepared.warning, true)
  assert.ok(prepared.delayMs >= 9000 && prepared.delayMs <= 10000, `delay ${prepared.delayMs}`)
  await deny('early tier 3 confirm', http('permission/commit', { peerId: peerIdA.id, tier: 3, nonce: prepared.nonce, password: PASSWORD }), 'confirm-too-early')
  await new Promise((done) => setTimeout(done, 10400))
  const grant3 = await http('permission/commit', { peerId: peerIdA.id, tier: 3, nonce: prepared.nonce, password: PASSWORD })
  assert.equal(grant3.peer.tier, 3)
  log('tier 3 confirmed after the delay')

  log('chat with the local DSH through the peer (this runs a real agent turn)')
  const chat = await peerAConnected.call('chat.send', { text: 'Reply with exactly PEERWEAVE-OK and nothing else.' }, 120000)
  assert.equal(typeof chat.reply, 'string')
  assert.ok(chat.reply.trim().length > 0)
  log(`chat reply: ${chat.reply.slice(0, 120).replace(/\s+/g, ' ')}`)

  log('outgoing dial: the stand-in hosts an invite and this host joins it')
  peerB = new PeerProcess(['--state', join(TMP, 'peer-b'), '--listen', '41338', '--name', 'Standalone B'])
  const inviteB = await peerB.waitFor((event) => event.event === 'invite', 15000)
  await http('invite/accept', { code: inviteB.code, transport: 'tcp' })
  await peerB.waitFor((event) => event.event === 'connected', 20000)
  const peerIdB = await waitUntil('peer B in public state', async () => {
    const next = await http('public', undefined, { noToken: true })
    const peer = next.peers.find((entry) => entry.name === 'Standalone B')
    return peer && peer.connected && peer.direction === 'outbound' ? peer : null
  })
  log(`outgoing link okay: ${peerIdB.direction} to ${peerIdB.host}:${peerIdB.port}`)
  await tierChange(peerIdB.id, 1)
  await waitUntil('peer B sees tier 1', () => peerB.waitFor((event) => event.event === 'grant' && event.tier === 1, 5000))
  const historyB = await peerB.call('history.list')
  assert.ok(Array.isArray(historyB.sessions))
  log(`outgoing link serves tier 1: ${historyB.sessions.length} sessions`)

  log('password and token gates')
  await deny('wrong password', http('permission/prepare', { peerId: peerIdA.id, tier: 1, password: 'not-the-password' }), 'bad-password')
  const savedToken = token
  token = null
  await deny('missing token', http('permission/prepare', { peerId: peerIdA.id, tier: 1, password: PASSWORD }), 'token-required')
  token = savedToken
  log('gates held')

  log('reset the test vault (delivery should start with no password)')
  await http('reset', { password: PASSWORD })
  const resetState = await http('public', undefined, { noToken: true })
  assert.equal(resetState.passwordSet, false)
  assert.equal(resetState.peers.length, 0)
  token = null
  log('reset okay')
} catch (error) {
  exitCode = 1
  console.error('\nE2E FAILED:', error && error.stack ? error.stack : error)
  if (runningPeerA && runningPeerA.stderr) console.error('peer A stderr:', runningPeerA.stderr.slice(-1500))
  if (peerB && peerB.stderr) console.error('peer B stderr:', peerB.stderr.slice(-1500))
} finally {
  try {
    if (runningPeerA) await runningPeerA.close()
    if (peerB) await peerB.close()
  } catch {
    /* ignore */
  }
  await rm(IMPORTS, { recursive: true, force: true }).catch(() => {})
  await rm(TMP, { recursive: true, force: true }).catch(() => {})
  process.exit(exitCode)
}
