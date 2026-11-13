/**
 * Cross-network transport tests: relay pairing, custom dial address/port, and
 * IPv6/dual-stack listening. Uses two complete Peerweave services in-process.
 */
import assert from 'node:assert/strict'
import net from 'node:net'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PeerweaveService } from '../lib/service.js'
import { startRelayServer } from '../lib/relay-server.js'
import { openRelay } from '../lib/relay-client.js'

const ROOT = await mkdtemp(join(tmpdir(), 'peerweave-net-'))
const WORKSPACE_A = join(ROOT, 'workspace-a')
const WORKSPACE_B = join(ROOT, 'workspace-b')
const PASS_A = 'alpha-password-123'
const PASS_B = 'bravo-password-456'
const IP = '127.0.0.1'

function log(message) {
  process.stdout.write(`ok: ${message}\n`)
}

async function waitUntil(label, fn, timeoutMs = 10000) {
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
    await new Promise((done) => setTimeout(done, 150))
  }
  throw new Error(`${label} did not settle: ${last instanceof Error ? last.message : String(last)}`)
}

function fakes(workspace, label) {
  return {
    controller: {
      async list() {
        return { items: [{ sessionId: `session-${label}`, updatedAt: Date.now(), running: false, blank: false, cwd: workspace }] }
      },
      async events() {
        return { records: [{ type: 'event', event: { type: 'user/message', seq: 1, time: Date.now(), data: { role: 'user', content: [{ type: 'text', text: `hello ${label}` }] } } }], hasMore: false }
      },
      async state() {
        return { cursor: 0, active: false, running: false, queue: null, pendingInput: [] }
      },
      async create() {
        return { sessionId: `session-${label}-guest` }
      },
      async prompt() {
        return { accepted: true }
      },
      async wait() {
        return { reason: 'idle', state: { cursor: 1 }, output: { records: [], truncated: false } }
      },
      async rename() {
        return {}
      },
    },
    query: {
      async readTitle() {
        return { title: `Fixture ${label}` }
      },
      async readTitleSnapshots(ids) {
        return ids.map((sessionId) => ({ sessionId, status: 'fulfilled', value: { title: { title: `Fixture ${label}` } } }))
      },
    },
    registry: { async archiveSession() {} },
  }
}

async function createService(name, workspace, port, dataDir, bindHost = '0.0.0.0', extraConfig = {}) {
  const fake = fakes(workspace, name)
  const service = new PeerweaveService({
    ctx: {},
    config: {
      dataDir,
      listenPort: port,
      advertiseHost: '127.0.0.1',
      sharedRoot: workspace,
      maxFileBytes: 4 * 1024 * 1024,
      ...extraConfig,
    },
    log: () => {},
  })
  service.attach({
    controller: fake.controller,
    query: fake.query,
    workingDirectory: { defaultDirectory: workspace },
    registry: fake.registry,
  })
  await service.ready
  await service.setup(name === 'alpha' ? PASS_A : PASS_B, `${name} host`, IP)
  await waitUntil(`${name} listener`, async () => (service.server ? true : null))
  if (bindHost !== '0.0.0.0') {
    await service.updateSettings({ bindHost }, name === 'alpha' ? PASS_A : PASS_B, IP)
    await waitUntil(`${name} ${bindHost} listener`, async () => (service.server ? true : null))
  }
  return service
}

function peerOf(service, other) {
  return service.store.peers().find((entry) => entry.id === other.identity.fingerprint)
}

function tryConnect(host, port) {
  return new Promise((resolvePromise) => {
    const socket = net.connect({ host, port })
    const done = (value) => {
      socket.destroy()
      resolvePromise(value)
    }
    socket.once('connect', () => done(true))
    socket.once('error', () => done(false))
    const timer = setTimeout(() => done(false), 800)
    timer.unref?.()
  })
}

let exitCode = 0
let relay = null
let A = null
let B = null
try {
  await mkdir(WORKSPACE_A, { recursive: true })
  await mkdir(WORKSPACE_B, { recursive: true })
  await writeFile(join(WORKSPACE_A, 'a.txt'), 'alpha\n')
  await writeFile(join(WORKSPACE_B, 'b.txt'), 'bravo\n')

  // A fake `ssh -R` executable lets the test exercise the reverse-tunnel path
  // without a real VPS: it listens on the requested port and forwards to the
  // DSH listener, which is exactly what remote port forwarding does.
  const fakeSsh = join(ROOT, 'fake-ssh.mjs')
  await writeFile(fakeSsh, `
import net from 'node:net'
const args = process.argv.slice(2)
const index = args.indexOf('-R')
if (index < 0) process.exit(2)
const [bindAddress, bindPort, targetHost, targetPort] = args[index + 1].split(':')
const server = net.createServer((client) => {
  const upstream = net.connect({ host: targetHost, port: Number(targetPort) })
  const close = () => { client.destroy(); upstream.destroy() }
  client.on('error', close)
  upstream.on('error', close)
  client.on('close', () => upstream.destroy())
  upstream.on('close', () => client.destroy())
  client.pipe(upstream)
  upstream.pipe(client)
})
server.on('error', () => process.exit(1))
server.listen(Number(bindPort), bindAddress)
const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 200).unref() }
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
setInterval(() => {}, 1000000)
`)

  relay = await startRelayServer({ host: '127.0.0.1', port: 0, token: 'relay-token' })
  const sshConfig = { sshCommand: process.execPath, sshPrefixArgs: [fakeSsh] }
  A = await createService('alpha', WORKSPACE_A, 41441, join(ROOT, 'state-a'), '0.0.0.0', sshConfig)
  B = await createService('bravo', WORKSPACE_B, 41451, join(ROOT, 'state-b'), '0.0.0.0', sshConfig)
  log(`relay on 127.0.0.1:${relay.port}`)

  // A wrong relay token must be rejected.
  await assert.rejects(
    openRelay({ host: '127.0.0.1', port: relay.port, room: 'a'.repeat(32), role: 'host', token: 'wrong', waitForPeer: false, waitTimeoutMs: 5000 }),
    (error) => error.code === 'unauthorized',
  )
  log('relay token check')

  await A.updateSettings({ relayClient: { host: '127.0.0.1', port: relay.port, token: 'relay-token' } }, PASS_A, IP)
  const relayInvite = await A.createInvite(PASS_A, IP, { mode: 'relay' })
  assert.equal(relayInvite.mode, 'relay')
  assert.ok(relayInvite.code.startsWith('PW1-'))
  log(`relay invite created for ${relayInvite.relay.host}:${relayInvite.relay.port}`)

  const joined = await B.acceptInvite({ code: relayInvite.code }, IP)
  assert.ok(joined.peer)
  const peerAOnB = await waitUntil('B knows A', () => peerOf(B, A))
  const peerBOnA = await waitUntil('A knows B', () => peerOf(A, B))
  await waitUntil('relay link both sides', async () => {
    const linkA = A.links.get(peerBOnA.id)
    const linkB = B.links.get(peerAOnB.id)
    return linkA && linkA.open && linkB && linkB.open ? true : null
  })
  assert.equal(B.store.peer(peerAOnB.id).transport, 'relay')
  assert.equal(B.store.peer(peerAOnB.id).relay.role, 'join')
  assert.equal(A.store.peer(peerBOnA.id).relay.role, 'host')
  log('relay pairing and end-to-end handshake')

  const prepared = await A.prepareGrant(peerBOnA.id, 1, PASS_A, IP)
  await A.commitGrant(peerBOnA.id, 1, prepared.nonce, PASS_A, IP)
  const history = await B.remoteCall(peerAOnB.id, 'history.list', {})
  assert.equal(history.sessions.length, 1)
  log('tier 1 history over the relay')

  // Remove both peers so the next test can pair fresh.
  await A.removePeer(peerBOnA.id, PASS_A, IP)
  await B.removePeer(peerAOnB.id, PASS_B, IP)

  // Custom dial address/port: the invite advertises an unreachable TEST-NET
  // address; B overrides it with 127.0.0.1 and the real port.
  await A.updateSettings({ advertiseHost: '192.0.2.1' }, PASS_A, IP)
  const directInvite = await A.createInvite(PASS_A, IP)
  assert.equal(directInvite.host, '192.0.2.1')
  const directJoin = await B.acceptInvite(
    { code: directInvite.code, dialHost: '127.0.0.1', dialPort: directInvite.port },
    IP,
  )
  assert.ok(directJoin.peer)
  const customPeer = await waitUntil('custom dial peer', () => peerOf(B, A))
  assert.equal(customPeer.host, '127.0.0.1')
  assert.equal(customPeer.port, directInvite.port)
  log('custom dial host/port override')

  await assert.rejects(
    A.updateSettings({ reverseSsh: { enabled: true, target: '', bindPort: 41471 } }, PASS_A, IP),
    (error) => error.code === 'bad-request',
  )
  await assert.rejects(
    A.updateSettings({ reverseSsh: { enabled: true, target: 'user@vps.example.com', bindPort: 80 } }, PASS_A, IP),
    (error) => error.code === 'bad-port',
  )
  log('reverse SSH settings validation')

  await A.removePeer(peerBOnA.id !== undefined ? peerBOnA.id : peerOf(A, B).id, PASS_A, IP)
  await B.removePeer(customPeer.id, PASS_B, IP)

  // IPv6 / dual-stack listening. Some Windows sandboxes block ::1 connects,
  // so verify the :: bind and reach the same listener over its IPv4 half.
  await A.updateSettings({ bindHost: '::', advertiseHost: '::1' }, PASS_A, IP)
  await waitUntil('dual-stack listener', async () => (A.server && A.publicState().listening.bindHost === '::' ? true : null))
  assert.equal(A.publicState().listening.bindHost, '::')
  const v6Invite = await A.createInvite(PASS_A, IP)
  assert.equal(v6Invite.host, '::1')
  const v6Join = await B.acceptInvite(
    { code: v6Invite.code, dialHost: '127.0.0.1', dialPort: v6Invite.port },
    IP,
  )
  assert.ok(v6Join.peer)
  log('IPv6/dual-stack bind (IPv4 half reached; native ::1 may be blocked by the OS)')

  await A.removePeer(peerOf(A, B).id, PASS_A, IP)
  await B.removePeer(peerOf(B, A).id, PASS_B, IP)

  // Reverse SSH path with a fake ssh -R executable forwarding to the DSH port.
  await A.updateSettings(
    {
      advertiseHost: '127.0.0.1',
      reverseSsh: { enabled: true, target: 'fake@vps', bindPort: 41777, extraArgs: '' },
    },
    PASS_A,
    IP,
  )
  await waitUntil('reverse ssh listener', async () => ((await tryConnect('127.0.0.1', 41777)) ? true : null), 10000)
  assert.equal(A.publicState().reverseSsh.running, true)
  const reverseInvite = await A.createInvite(PASS_A, IP)
  assert.equal(reverseInvite.host, '127.0.0.1')
  assert.equal(reverseInvite.port, 41777)
  const reverseJoin = await B.acceptInvite({ code: reverseInvite.code }, IP)
  assert.ok(reverseJoin.peer)
  log('reverse SSH tunnel path and invite endpoint')
  await A.updateSettings(
    { reverseSsh: { enabled: false, target: 'fake@vps', bindPort: 41777, extraArgs: '' } },
    PASS_A,
    IP,
  )

  console.log('\ncross-network tests passed')
} catch (error) {
  exitCode = 1
  console.error('\nNETWORK TEST FAILED:', error && error.stack ? error.stack : error)
} finally {
  try {
    A?.dispose()
    B?.dispose()
    if (relay) await relay.close()
  } catch {
    /* ignore */
  }
  await rm(ROOT, { recursive: true, force: true }).catch(() => {})
  process.exit(exitCode)
}
