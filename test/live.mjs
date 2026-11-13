/**
 * Live integration test: drives the final Peerweave Host source loaded by the
 * temporary `dsh-peerweave-selftest` bundle inside the running DSH process, so
 * real session history, real workspace files, real guest-agent chat and the
 * real web carrier are exercised.
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
const NS = '/peerweave-selftest'
const PASSWORD = 'selftest-password-123'
const TMP = join(HERE, '.live')
const IMPORTS = join(dirname(HERE), 'peerweave-imports')
let token = null

function log(message) {
  process.stdout.write(`\n== ${message}\n`)
}

async function http(action, body, options = {}) {
  const headers = { 'x-peerweave': '1' }
  if (!options.noToken && token) headers['x-peerweave-token'] = token
  if (body !== undefined) headers['content-type'] = 'application/json'
  const response = await fetch(`${BASE}${NS}/${action}`, {
    method: options.method || (body === undefined ? 'GET' : 'POST'),
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => null)
  if (!payload) throw new Error(`${action}: HTTP ${response.status}`)
  if (!payload.ok) {
    const error = new Error(payload.error && payload.error.message)
    error.code = payload.error && payload.error.code
    throw error
  }
  return payload.data === undefined ? payload : payload.data
}

async function waitUntil(label, fn, timeoutMs = 20000, intervalMs = 300) {
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
  throw new Error(`${label} did not settle: ${last instanceof Error ? last.message : String(last)}`)
}

class PeerProcess {
  constructor(args) {
    this.child = spawn(process.execPath, [PEER_SCRIPT, ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
    this.events = []
    this.waiters = []
    this.stderr = ''
    this.seq = 0
    readline.createInterface({ input: this.child.stdout }).on('line', (line) => {
      let event
      try {
        event = JSON.parse(line)
      } catch {
        return
      }
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
  }

  waitFor(match, timeoutMs = 20000) {
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
          rejectPromise(new Error(`event timed out; stderr=${this.stderr.slice(-600)}`))
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
    }, 400)
  }
}

async function expectFailure(label, promise, code) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.code, code, `${label}: expected ${code}, got ${error.code}: ${error.message}`)
    log(`${label}: refused with ${code}`)
    return
  }
  throw new Error(`${label}: expected ${code}, but the call succeeded`)
}

async function grant(peerId, tier, waitMs = 0) {
  const prepared = await http('permission/prepare', { peerId, tier, password: PASSWORD })
  if (waitMs) await new Promise((done) => setTimeout(done, waitMs))
  return http('permission/commit', { peerId, tier, nonce: prepared.nonce, password: PASSWORD })
}

let peerA = null
let peerB = null
let exitCode = 0

try {
  log('wait for the selftest bundle to create its vault')
  await waitUntil('selftest public state', async () => {
    const state = await http('public', undefined, { noToken: true })
    return state.passwordSet && state.unlocked ? state : null
  }, 30000)
  const unlocked = await http('unlock', { password: PASSWORD }, { noToken: true })
  token = unlocked.token
  const state = await http('public', undefined, { noToken: true })
  assert.equal(state.listening.active, true)
  log(`selftest identity ${state.fingerprint}, listener ${state.listening.port}`)

  log('create an invite and join it with a stand-in peer')
  const invite = await http('invite/create', { password: PASSWORD })
  peerA = new PeerProcess(['--state', join(TMP, 'peer-a'), '--join', invite.code, '--name', 'Standalone A'])
  const joined = await peerA.waitFor((event) => event.event === 'connected')
  log(`peer A joined as ${joined.fingerprint}`)
  const peerAState = await waitUntil('peer A visible', async () => {
    const next = await http('public', undefined, { noToken: true })
    return next.peers.find((peer) => peer.name === 'Standalone A' && peer.connected) || null
  })

  await expectFailure('tier 0 history', peerA.call('history.list'), 'permission-denied')
  await grant(peerAState.id, 1)
  const history = await peerA.call('history.list')
  assert.ok(history.sessions.length > 0, 'expected real sessions in D:\\study')
  const transcript = await peerA.call('history.read', { sessionId: history.sessions[0].id })
  assert.ok(transcript.messages.length > 0, 'expected real transcript messages')
  log(`real history: ${history.sessions.length} sessions; ${transcript.messages.length} messages from ${transcript.sessionId.slice(0, 22)}…`)

  await grant(peerAState.id, 2)
  const root = await peerA.call('files.list', { path: '' })
  assert.ok(root.entries.some((entry) => entry.name === 'dsh-peerweave'))
  const pkg = await peerA.call('files.read', { path: 'dsh-peerweave/package.json' })
  assert.ok(pkg.text.includes('"name": "dsh-peerweave"'))
  log(`real files: ${root.entries.length} root entries, package.json ${pkg.bytes} bytes`)

  await http('settings/update', { password: PASSWORD, patch: { maxFileBytes: 1024 } })
  await expectFailure('size cap', peerA.call('files.read', { path: 'dsh-peerweave/client.js' }), 'file-too-large')
  await http('settings/update', { password: PASSWORD, patch: { maxFileBytes: 4 * 1024 * 1024 } })
  log('real size cap enforced and restored')

  log('peer grants this host tier 2; read and copy a peer file')
  peerA.send({ op: 'setGrantToPeer', tier: 2 })
  await waitUntil('remote tier 2', async () => {
    const next = await http('public', undefined, { noToken: true })
    const peer = next.peers.find((entry) => entry.id === peerAState.id)
    return peer && peer.remoteTier === 2 ? peer : null
  })
  const remoteFile = await http('remote/files/read', { peerId: peerAState.id, path: 'standin.txt' })
  assert.ok(remoteFile.text.includes('stand-in peer'))
  const copied = await http('remote/copy', { peerId: peerAState.id, path: 'standin.txt' })
  assert.ok((await readFile(copied.localPath, 'utf8')).includes('stand-in peer'))
  log(`copied peer file to ${copied.localPath}`)

  log('tier 3 with the enforced 10-second confirmation')
  const prepared = await http('permission/prepare', { peerId: peerAState.id, tier: 3, password: PASSWORD })
  assert.equal(prepared.warning, true)
  await expectFailure('early tier 3', http('permission/commit', { peerId: peerAState.id, tier: 3, nonce: prepared.nonce, password: PASSWORD }), 'confirm-too-early')
  await new Promise((done) => setTimeout(done, 10400))
  await http('permission/commit', { peerId: peerAState.id, tier: 3, nonce: prepared.nonce, password: PASSWORD })
  log('tier 3 confirmed after the delay')

  log('chat with the real local DSH agent (runs one real turn)')
  const chat = await peerA.call('chat.send', { text: 'Reply with exactly PEERWEAVE-OK and nothing else.' }, 150000)
  assert.equal(typeof chat.reply, 'string')
  assert.ok(chat.reply.trim().length > 0)
  log(`chat reply (${chat.reason}): ${chat.reply.slice(0, 160).replace(/\s+/g, ' ')}`)

  log('outgoing dial with a second stand-in host')
  peerB = new PeerProcess(['--state', join(TMP, 'peer-b'), '--listen', '41339', '--name', 'Standalone B'])
  const inviteB = await peerB.waitFor((event) => event.event === 'invite', 15000)
  await http('invite/accept', { code: inviteB.code, transport: 'tcp' })
  await peerB.waitFor((event) => event.event === 'connected')
  const peerBState = await waitUntil('peer B visible', async () => {
    const next = await http('public', undefined, { noToken: true })
    const peer = next.peers.find((entry) => entry.name === 'Standalone B')
    return peer && peer.connected && peer.direction === 'outbound' ? peer : null
  })
  await grant(peerBState.id, 1)
  const historyB = await peerB.call('history.list')
  assert.ok(historyB.sessions.length > 0)
  log(`outgoing link serves real history to peer B (${historyB.sessions.length} sessions)`)

  log('reset the selftest vault')
  const reset = await http('reset', { password: PASSWORD })
  assert.equal(reset.passwordSet, false)
  assert.equal(reset.peers.length, 0)
  token = null
  log('selftest reset')
  console.log('\nlive integration test passed')
} catch (error) {
  exitCode = 1
  console.error('\nLIVE TEST FAILED:', error && error.stack ? error.stack : error)
  if (peerA && peerA.stderr) console.error('peer A stderr:', peerA.stderr.slice(-1200))
  if (peerB && peerB.stderr) console.error('peer B stderr:', peerB.stderr.slice(-1200))
} finally {
  try {
    if (peerA) await peerA.close()
    if (peerB) await peerB.close()
  } catch {
    /* ignore */
  }
  await rm(IMPORTS, { recursive: true, force: true }).catch(() => {})
  await rm(TMP, { recursive: true, force: true }).catch(() => {})
  process.exit(exitCode)
}
