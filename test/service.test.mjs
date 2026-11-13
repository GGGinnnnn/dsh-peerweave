/**
 * In-process integration test for the delivered Peerweave Host service.
 *
 * Two full service instances (A and B) run in this Node process with their own
 * state directories and fake Harness session services. It exercises the real
 * invite flow, handshakes, the tier gates, history/file reads, the size cap,
 * copying a peer file into the local workspace, the enforced 10-second tier-3
 * delay, guest chat, password verification, traversal refusal and reset.
 */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PeerweaveService } from '../lib/service.js'

const ROOT = await mkdtemp(join(tmpdir(), 'peerweave-test-'))
const WORKSPACE_A = join(ROOT, 'workspace-a')
const WORKSPACE_B = join(ROOT, 'workspace-b')
const PASS_A = 'alpha-password-123'
const PASS_B = 'bravo-password-456'
const PEER_A_IP = '127.0.0.1'
const PEER_B_IP = '127.0.0.1'

function log(message) {
  process.stdout.write(`ok: ${message}\n`)
}

async function waitUntil(label, fn, timeoutMs = 8000) {
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
    await new Promise((done) => setTimeout(done, 100))
  }
  throw new Error(`${label} did not settle: ${last instanceof Error ? last.message : String(last)}`)
}

function createFakes(workspace, label) {
  const sessions = [
    { sessionId: `session-${label}-1`, updatedAt: Date.now(), running: false, blank: false, cwd: workspace },
    { sessionId: `session-${label}-2`, updatedAt: Date.now() - 1000, running: false, blank: false, cwd: join(workspace, '..', 'outside') },
  ]
  const state = { chatText: '', guestSeq: 0 }
  const controller = {
    async list() {
      return { items: sessions }
    },
    async events(request) {
      return {
        records: [
          { type: 'event', event: { type: 'user/message', seq: 1, time: Date.now(), data: { role: 'user', content: [{ type: 'text', text: `hello from ${label}` }] } } },
          { type: 'event', event: { type: 'assistant/message', seq: 2, time: Date.now(), data: { turn: 1, step: 1, message: { role: 'assistant', content: [{ type: 'text', text: 'assistant reply' }] } } } },
        ],
        hasMore: false,
      }
    },
    async state() {
      return { cursor: 0, active: false, running: false, queue: null, pendingInput: [] }
    },
    async create() {
      state.guestSeq += 1
      return { sessionId: `session-${label}-guest-${state.guestSeq}` }
    },
    async prompt(request) {
      state.chatText = request.content[0].text
      return { accepted: true }
    },
    async wait() {
      return {
        reason: 'idle',
        state: { cursor: 1 },
        output: {
          records: [
            { type: 'event', event: { type: 'assistant/message', seq: 10, time: Date.now(), data: { message: { role: 'assistant', content: [{ type: 'text', text: `echo: ${state.chatText}` }] } } } },
          ],
          truncated: false,
        },
      }
    },
    async rename() {
      return {}
    },
  }
  const query = {
    async readTitle() {
      return { title: `Fixture ${label}` }
    },
    async readTitleSnapshots(ids) {
      return ids.map((sessionId) => ({ sessionId, status: 'fulfilled', value: { title: { title: `Fixture ${label}` } } }))
    },
  }
  const registry = {
    archived: [],
    list() {
      return [{ id: `ws-${label}`, path: workspace, title: `Workspace ${label}` }]
    },
    get(id) {
      return id === `ws-${label}` ? { id, path: workspace, title: `Workspace ${label}` } : undefined
    },
    async archiveSession(sessionId) {
      this.archived.push(sessionId)
    },
  }
  return { controller, query, registry }
}

async function createService(name, workspace, port, dataDir) {
  const fake = createFakes(workspace, name)
  const service = new PeerweaveService({
    ctx: {},
    config: {
      dataDir,
      listenPort: port,
      advertiseHost: '127.0.0.1',
      sharedRoot: workspace,
      maxFileBytes: 1024 * 1024,
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
  return { service, fake }
}

async function expectFailure(label, promise, code) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.code, code, `${label}: expected ${code}, got ${error.code}: ${error.message}`)
    log(`${label} refused with ${code}`)
    return
  }
  throw new Error(`${label}: expected ${code}, but the call succeeded`)
}

async function peerOf(service, other) {
  const peer = service.store.peers().find((entry) => entry.id === other.service.identity.fingerprint)
  assert.ok(peer, 'peer record missing')
  return peer
}

let exitCode = 0
try {
  await mkdir(join(WORKSPACE_A, 'sub'), { recursive: true })
  await mkdir(join(WORKSPACE_B, 'sub'), { recursive: true })
  await writeFile(join(WORKSPACE_A, 'hello.txt'), 'hello from workspace A\n')
  await writeFile(join(WORKSPACE_A, 'sub', 'inner.txt'), 'inner file\n')
  await writeFile(join(WORKSPACE_A, 'big.bin'), Buffer.alloc(4096, 7))
  await writeFile(join(WORKSPACE_B, 'bravo.txt'), 'bravo file\n')
  const largeSize = 12 * 1024 * 1024
  await writeFile(join(WORKSPACE_A, 'large.bin'), Buffer.alloc(largeSize, 5))
  await writeFile(join(WORKSPACE_B, 'large.bin'), Buffer.alloc(largeSize, 6))

  const A = await createService('alpha', WORKSPACE_A, 41401, join(ROOT, 'state-a'))
  const B = await createService('bravo', WORKSPACE_B, 41411, join(ROOT, 'state-b'))
  log('two services listen')

  const tokenA = await A.service.setup(PASS_A, 'Alpha host', PEER_A_IP)
  const tokenB = await B.service.setup(PASS_B, 'Bravo host', PEER_B_IP)
  assert.ok(tokenA.token && tokenB.token)
  await waitUntil('A unlocked listener', async () => (A.service.server ? true : null))
  await waitUntil('B unlocked listener', async () => (B.service.server ? true : null))
  log(`vaults created; A=${A.service.identity.fingerprint.slice(0, 12)}… B=${B.service.identity.fingerprint.slice(0, 12)}…`)

  await expectFailure('setup twice', A.service.setup(PASS_A, 'again', PEER_A_IP), 'already-configured')
  await expectFailure('wrong password', A.service.authenticate('wrong-password', PEER_A_IP), 'bad-password')

  const invite = await A.service.createInvite(PASS_A, PEER_A_IP)
  assert.ok(invite.code.startsWith('PW1-'))
  assert.equal(invite.host, '127.0.0.1')
  log(`A created an invite on port ${invite.port}`)

  const joined = await B.service.acceptInvite({ code: invite.code }, PEER_B_IP)
  assert.ok(joined.peer)
  const peerAOnB = await waitUntil('B knows A', () => peerOf(B.service, A), 8000)
  const peerBOnA = await waitUntil('A knows B', () => peerOf(A.service, B), 8000)
  await waitUntil('A link', () => (A.service.links.has(peerBOnA.id) ? true : null))
  await waitUntil('B link', () => (B.service.links.has(peerAOnB.id) ? true : null))
  log('invite pairing established both ways')

  await expectFailure('tier 0 history', B.service.remoteCall(peerAOnB.id, 'history.list', {}), 'permission-denied')
  await expectFailure('tier 0 files', B.service.remoteCall(peerAOnB.id, 'files.list', { path: '' }), 'permission-denied')
  log('tier 0 only answers info')

  const prepared1 = await A.service.prepareGrant(peerBOnA.id, 1, PASS_A, PEER_A_IP)
  assert.equal(prepared1.delayMs, 0)
  await A.service.commitGrant(peerBOnA.id, 1, prepared1.nonce, PASS_A, PEER_A_IP)
  const history = await B.service.remoteCall(peerAOnB.id, 'history.list', {})
  assert.equal(history.sessions.length, 2, 'all sessions across workspaces are exposed')
  assert.ok(Array.isArray(history.workspaces) && history.workspaces.length >= 1)
  assert.equal(history.workspaces[0].title, 'Workspace alpha')
  assert.equal(history.sessions[0].title, 'Fixture alpha')
  const transcript = await B.service.remoteCall(peerAOnB.id, 'history.read', { sessionId: history.sessions[0].id })
  assert.equal(transcript.messages.length, 2)
  assert.equal(transcript.messages[0].text, 'hello from alpha')
  log('tier 1 history exposes all workspaces, grouped by workspace')
  await expectFailure('tier 1 files', B.service.remoteCall(peerAOnB.id, 'files.list', { path: '' }), 'permission-denied')

  const prepared2 = await A.service.prepareGrant(peerBOnA.id, 2, PASS_A, PEER_A_IP)
  await A.service.commitGrant(peerBOnA.id, 2, prepared2.nonce, PASS_A, PEER_A_IP)
  const fileWorkspaces = await B.service.remoteCall(peerAOnB.id, 'files.workspaces', {})
  assert.equal(fileWorkspaces.workspaces[0].title, 'Workspace alpha')
  const listing = await B.service.remoteCall(peerAOnB.id, 'files.list', { path: '', workspaceId: fileWorkspaces.workspaces[0].id })
  assert.ok(listing.entries.some((entry) => entry.name === 'hello.txt'))
  assert.ok(listing.entries.some((entry) => entry.name === 'sub' && entry.type === 'dir'))
  const file = await B.service.remoteCall(peerAOnB.id, 'files.read', { path: 'sub/inner.txt', workspaceId: fileWorkspaces.workspaces[0].id })
  assert.equal(file.text, 'inner file\n')
  log('tier 2 file access selects any workspace')
  await expectFailure('traversal', B.service.remoteCall(peerAOnB.id, 'files.read', { path: '../workspace-b/bravo.txt' }), 'invalid-path')
  log('tier 2 file list/read works and traversal is refused')

  await A.service.updateSettings({ maxFileBytes: 64 }, PASS_A, PEER_A_IP)
  await expectFailure('size cap', B.service.remoteCall(peerAOnB.id, 'files.read', { path: 'big.bin' }), 'file-too-large')
  await A.service.updateSettings({ maxFileBytes: 1024 * 1024 }, PASS_A, PEER_A_IP)
  log('file size limit is enforced')

  const preparedB = await B.service.prepareGrant(peerAOnB.id, 2, PASS_B, PEER_B_IP)
  await B.service.commitGrant(peerAOnB.id, 2, preparedB.nonce, PASS_B, PEER_B_IP)
  const copied = await A.service.copyFromPeer(peerBOnA.id, 'bravo.txt')
  assert.equal(await readFile(copied.localPath, 'utf8'), 'bravo file\n')
  assert.ok(copied.localPath.includes('peerweave-imports'))
  const copiedFromWorkspace = await A.service.copyFromPeer(peerBOnA.id, 'bravo.txt', 'ws-bravo')
  assert.equal(await readFile(copiedFromWorkspace.localPath, 'utf8'), 'bravo file\n')
  log('copy from the peer into the local workspace works')

  await A.service.updateSettings({ maxFileBytes: 64 * 1024 * 1024 }, PASS_A, PEER_A_IP)
  await expectFailure('inline preview cap', B.service.remoteCall(peerAOnB.id, 'files.read', { path: 'large.bin' }), 'file-needs-transfer')
  const chunk = await B.service.remoteCall(peerAOnB.id, 'files.readChunk', { path: 'large.bin', offset: 0, length: 1024 * 1024 })
  assert.equal(chunk.bytes, 1024 * 1024)
  assert.equal(chunk.totalBytes, largeSize)
  assert.equal(chunk.eof, false)
  await B.service.updateSettings({ maxFileBytes: 64 * 1024 * 1024 }, PASS_B, PEER_B_IP)
  const largeCopy = await A.service.copyFromPeer(peerBOnA.id, 'large.bin')
  assert.equal(largeCopy.bytes, largeSize)
  assert.equal((await stat(largeCopy.localPath)).size, largeSize)
  log(`large file: inline read capped, ${largeCopy.bytes} bytes copied through chunks`)

  const prepared3 = await A.service.prepareGrant(peerBOnA.id, 3, PASS_A, PEER_A_IP)
  assert.equal(prepared3.warning, true)
  assert.ok(prepared3.delayMs >= 9000)
  await expectFailure('early tier 3', A.service.commitGrant(peerBOnA.id, 3, prepared3.nonce, PASS_A, PEER_A_IP), 'confirm-too-early')
  await new Promise((done) => setTimeout(done, 10200))
  await A.service.commitGrant(peerBOnA.id, 3, prepared3.nonce, PASS_A, PEER_A_IP)
  const chat = await B.service.remoteCall(peerAOnB.id, 'chat.send', { text: 'ping from B' }, 30000)
  assert.equal(chat.reply, 'echo: ping from B')
  const guestPeer = A.service.store.peer(peerBOnA.id)
  assert.ok(guestPeer.guestSessionId, 'the guest session was created')
  log('tier 3 waits 10s, then chats through a guest session')

  const preparedBad = await A.service.prepareGrant(peerBOnA.id, 1, PASS_A, PEER_A_IP)
  await expectFailure('bad commit password', A.service.commitGrant(peerBOnA.id, 1, preparedBad.nonce, 'nope-nope-nope', PEER_A_IP), 'bad-password')
  await expectFailure('unknown nonce', A.service.commitGrant(peerBOnA.id, 1, 'deadbeef', PASS_A, PEER_A_IP), 'grant-expired')
  log('permission commits require the password and a prepared nonce')

  await B.service.changePassword(PASS_B, 'new-bravo-password', PEER_B_IP)
  await expectFailure('old password', B.service.authenticate(PASS_B, PEER_B_IP), 'bad-password')
  await B.service.authenticate('new-bravo-password', PEER_B_IP)
  log('password change re-seals the identity key')

  const reloaded = new PeerweaveService({
    ctx: {},
    config: { dataDir: join(ROOT, 'state-a'), listenPort: 41431, advertiseHost: '127.0.0.1' },
    log: () => {},
  })
  await reloaded.ready
  assert.equal(reloaded.store.passwordSet, true)
  await reloaded.unlock(PASS_A, PEER_A_IP)
  assert.equal(reloaded.identity.fingerprint, A.service.identity.fingerprint)
  reloaded.dispose()
  log('identity survives a fresh service load and unlock')

  const otherPeerOnA = A.service.store.peer(peerBOnA.id)
  await A.service.removePeer(peerBOnA.id, PASS_A, PEER_A_IP)
  assert.equal(A.service.store.peer(peerBOnA.id), undefined)
  assert.ok(A.fake.registry.archived.includes(otherPeerOnA.guestSessionId))
  log('removing a peer forgets it and archives its guest session')

  await expectFailure('reset needs password', A.service.reset('wrong-password', PEER_A_IP), 'bad-password')
  const reset = await A.service.reset(PASS_A, PEER_A_IP)
  assert.equal(reset.passwordSet, false)
  assert.equal(reset.peers.length, 0)
  assert.equal(A.service.identity, null)
  log('reset erases the vault')

  const recovery = await B.service.forceResetPrepare(PEER_B_IP)
  assert.equal(recovery.delayMs, 10000)
  await expectFailure('early force reset', B.service.forceResetCommit(recovery.nonce, 'ERASE', PEER_B_IP), 'confirm-too-early')
  await expectFailure('force reset phrase', B.service.forceResetCommit(recovery.nonce, 'nope', PEER_B_IP), 'bad-request')
  await new Promise((done) => setTimeout(done, 10200))
  const wiped = await B.service.forceResetCommit(recovery.nonce, 'ERASE', PEER_B_IP)
  assert.equal(wiped.passwordSet, false)
  assert.equal(wiped.peers.length, 0)
  assert.equal(B.service.identity, null)
  log('forgot-password force clear waits 10s and erases the vault')

  B.service.dispose()
  A.service.dispose()
  console.log('\nservice integration tests passed')
} catch (error) {
  exitCode = 1
  console.error('\nSERVICE TEST FAILED:', error && error.stack ? error.stack : error)
} finally {
  await rm(ROOT, { recursive: true, force: true }).catch(() => {})
  process.exit(exitCode)
}
