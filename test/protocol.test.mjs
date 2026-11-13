/**
 * Protocol tests: authenticated handshake, invite proof, pinned identity,
 * and AES-GCM frame binding to direction/counter.
 */
import net from 'node:net'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import {
  SecureChannel,
  runInitiatorHandshake,
  runResponderHandshake,
} from '../lib/protocol.js'
import {
  aesDecrypt,
  aesEncrypt,
  b64u,
  generateIdentity,
  hmacSha256,
  privateKeyFromPem,
  timingSafeEq,
  unb64u,
} from '../lib/util.js'

function listen(server) {
  return new Promise((resolvePromise) => server.listen(0, '127.0.0.1', () => resolvePromise(server.address().port)))
}

function connect(port) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    socket.once('connect', () => resolvePromise(socket))
    socket.once('error', rejectPromise)
  })
}

async function pair(serverOptions, clientOptions) {
  const serverIdentity = generateIdentity()
  const clientIdentity = generateIdentity()
  const inviteKey = randomBytes(32)
  let serverResult = null
  let serverChannel = null
  const server = net.createServer(async (socket) => {
    const channel = new SecureChannel(socket)
    serverChannel = channel
    try {
      serverResult = await runResponderHandshake(channel, {
        identity: { publicRaw: serverIdentity.publicRaw, privateKey: privateKeyFromPem(serverIdentity.privatePem) },
        name: 'server',
        instanceId: 'server-instance',
        listenPort: 4444,
        lookupPeer: () => (serverOptions.known ? { publicRaw: clientIdentity.publicRaw, tier: serverOptions.tier || 0 } : undefined),
        verifyInvite: (id, digest, proof) => id === 'inv-1' && timingSafeEq(hmacSha256(inviteKey, digest), unb64u(proof)),
        tierFor: () => serverOptions.tier || 0,
        maxFileBytes: 2048,
        sharedLabel: 'shared-ws',
      })
      channel.onFrame((message) => {
        if (message.t === 'req') channel.send({ t: 'res', id: message.id, ok: true, value: { echo: message.args } })
        if (message.t === 'ping') channel.send({ t: 'pong' })
      })
    } catch (error) {
      try {
        channel.sendPlain({ t: 'pw/error', code: error.code || 'failed', message: error.message })
      } catch {
        /* peer already gone */
      }
      setTimeout(() => channel.socket.destroy(), 50)
    }
  })
  const port = await listen(server)
  const socket = await connect(port)
  const channel = new SecureChannel(socket)
  let result
  try {
    result = await runInitiatorHandshake(channel, {
      identity: { publicRaw: clientIdentity.publicRaw, privateKey: privateKeyFromPem(clientIdentity.privatePem) },
      name: 'client',
      instanceId: 'client-instance',
      listenPort: 5555,
      expectedPeerRaw: clientOptions.expectedPeerRaw === undefined ? serverIdentity.publicRaw : clientOptions.expectedPeerRaw,
      pair: clientOptions.pair === false ? undefined : { id: 'inv-1', key: clientOptions.inviteKey || inviteKey },
    })
  } catch (error) {
    socket.destroy()
    server.close()
    throw error
  }
  return { server, serverChannel, serverResult, channel, result, serverIdentity, clientIdentity, inviteKey }
}

async function testHappyPath() {
  const context = await pair({ known: true, tier: 2 }, { pair: false })
  assert.equal(context.result.peer.tier, 2)
  assert.equal(context.result.peer.sharedLabel, 'shared-ws')
  assert.equal(context.result.peer.maxFileBytes, 2048)
  assert.equal(context.result.peer.fingerprint.length, 64)
  const response = await new Promise((resolvePromise) => {
    context.channel.onFrame((message) => {
      if (message.t === 'res') resolvePromise(message.value)
    })
    context.channel.send({ t: 'req', id: '1', op: 'echo', args: { hello: 'world' } })
  })
  assert.deepEqual(response, { echo: { hello: 'world' } })
  context.channel.close()
  context.serverChannel.close()
  context.server.close()
  console.log('ok: authenticated handshake + sealed request/response')
}

async function testInviteRejected() {
  await assert.rejects(
    pair({ tier: 1 }, { inviteKey: randomBytes(32) }),
    (error) => error.code === 'bad-invite' || error.code === 'rejected',
  )
  console.log('ok: wrong invite secret is rejected')
}

async function testPinnedIdentity() {
  await assert.rejects(
    pair({ tier: 1 }, { expectedPeerRaw: randomBytes(32) }),
    (error) => error.code === 'identity-mismatch',
  )
  console.log('ok: a different peer identity is rejected')
}

function testFrames() {
  const key = randomBytes(32)
  const aad = 'session-1'
  const sealed = aesEncrypt(key, 1, aad, 'hello')
  assert.equal(aesDecrypt(key, 1, aad, sealed).toString('utf8'), 'hello')
  assert.throws(() => aesDecrypt(key, 2, aad, sealed))
  assert.throws(() => aesDecrypt(randomBytes(32), 1, aad, sealed))
  const otherAad = aesEncrypt(key, 1, 'session-2', 'hello')
  assert.throws(() => aesDecrypt(key, 1, aad, otherAad))
  console.log('ok: AES-GCM frames bind key, counter and session id')
}

await testHappyPath()
await testInviteRejected()
await testPinnedIdentity()
testFrames()
console.log('protocol tests passed')
