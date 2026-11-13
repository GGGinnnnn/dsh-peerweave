/**
 * Peerweave wire protocol.
 *
 * Handshake: mutual authentication with persistent Ed25519 identities and
 * forward secrecy from ephemeral X25519 keys. The joiner proves knowledge of a
 * single-use invite secret; the inviter's identity is pinned by the invite
 * fingerprint. Every later frame is AES-256-GCM with a per-direction counter
 * (implicit nonce) and a session-id AAD, so reordered or replayed frames fail.
 */
import {
  HANDSHAKE_MAX_FRAME,
  PROTOCOL_VERSION,
  aesDecrypt,
  aesEncrypt,
  b64u,
  domainHash,
  generateEphemeral,
  hkdf32,
  hmacSha256,
  publicKeyFromRaw,
  randomB64u,
  randomHex,
  sha256hex,
  signWith,
  timingSafeEq,
  toBuf,
  unb64u,
  verifyWith,
  x25519Shared,
} from './util.js'

export class HandshakeError extends Error {
  constructor(code, message) {
    super(message || code)
    this.name = 'HandshakeError'
    this.code = code
  }
}

export function helloDigest(helloCore) {
  return sha256hex(
    domainHash('pw1/hello', [
      helloCore.t,
      helloCore.v,
      helloCore.eph,
      helloCore.id,
      helloCore.nonce,
      helloCore.name,
      helloCore.instance,
      helloCore.listenPort,
    ]),
  )
}

export function challengeDigest(challengeCore) {
  return sha256hex(
    domainHash('pw1/challenge', [
      challengeCore.t,
      challengeCore.v,
      challengeCore.eph,
      challengeCore.id,
      challengeCore.nonce,
      challengeCore.name,
      challengeCore.instance,
      challengeCore.listenPort,
      challengeCore.sessionId,
      challengeCore.pairAccepted ? 1 : 0,
      challengeCore.yourTier,
      challengeCore.maxFileBytes,
      challengeCore.sharedLabel,
    ]),
  )
}

/** Channel wrapper: plaintext handshake frames, then sealed frames. */
export class SecureChannel {
  constructor(socket, options = {}) {
    this.socket = socket
    this.maxFrame = options.maxFrame || 8 * 1024 * 1024
    this.buffer = Buffer.alloc(0)
    this.sealed = false
    this.sendKey = null
    this.recvKey = null
    this.sessionId = null
    this.sendCounter = 1
    this.recvCounter = 1
    this.closed = false
    this.frameHandler = null
    this.closeHandler = null
    this.plainQueue = []
    this.plainWaiter = null
    this.closedError = null
    socket.on('data', (chunk) => this.onData(chunk))
    socket.on('error', (error) => this.fail(error))
    socket.on('close', () => this.fail(new Error('connection closed')))
  }

  get remoteAddress() {
    return this.socket.remoteAddress || ''
  }

  get remotePort() {
    return this.socket.remotePort || 0
  }

  onFrame(handler) {
    this.frameHandler = handler
  }

  onClose(handler) {
    this.closeHandler = handler
  }

  fail(error) {
    if (this.closed) return
    this.closed = true
    this.closedError = error instanceof Error ? error : new Error(String(error))
    if (this.plainWaiter) {
      const waiter = this.plainWaiter
      this.plainWaiter = null
      waiter.reject(this.closedError)
    }
    try {
      this.socket.destroy()
    } catch {
      /* ignore */
    }
    if (this.closeHandler) {
      try {
        this.closeHandler(this.closedError)
      } catch {
        /* ignore */
      }
    }
  }

  onData(chunk) {
    if (this.closed) return
    this.buffer = Buffer.concat([this.buffer, chunk])
    for (;;) {
      if (this.buffer.length < 4) return
      const length = this.buffer.readUInt32BE(0)
      const limit = this.sealed ? this.maxFrame : HANDSHAKE_MAX_FRAME
      if (length < 2 || length > limit) {
        this.fail(new Error('invalid frame length'))
        return
      }
      if (this.buffer.length < 4 + length) return
      const raw = this.buffer.subarray(4, 4 + length)
      this.buffer = this.buffer.subarray(4 + length)
      try {
        this.handleRaw(raw)
      } catch (error) {
        this.fail(error)
        return
      }
      if (this.closed) return
    }
  }

  handleRaw(raw) {
    if (this.sealed) {
      const counter = this.recvCounter
      if (counter > Number.MAX_SAFE_INTEGER) throw new Error('frame counter exhausted')
      const plain = aesDecrypt(this.recvKey, counter, this.sessionId, raw)
      this.recvCounter += 1
      let message
      try {
        message = JSON.parse(plain.toString('utf8'))
      } catch {
        throw new Error('malformed sealed frame')
      }
      this.deliver(message)
      return
    }
    let message
    try {
      message = JSON.parse(raw.toString('utf8'))
    } catch {
      throw new Error('malformed handshake frame')
    }
    if (this.plainWaiter) {
      const waiter = this.plainWaiter
      this.plainWaiter = null
      waiter.resolve(message)
      return
    }
    this.plainQueue.push(message)
  }

  deliver(message) {
    if (this.frameHandler) {
      this.frameHandler(message)
      return
    }
    this.plainQueue.push(message)
  }

  readPlain(timeoutMs = 15000) {
    if (this.plainQueue.length > 0) return Promise.resolve(this.plainQueue.shift())
    if (this.closed) return Promise.reject(this.closedError || new Error('connection closed'))
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        this.plainWaiter = null
        rejectPromise(new HandshakeError('handshake-timeout', 'handshake timed out'))
      }, timeoutMs)
      this.plainWaiter = {
        resolve: (value) => {
          clearTimeout(timer)
          resolvePromise(value)
        },
        reject: (error) => {
          clearTimeout(timer)
          rejectPromise(error)
        },
      }
    })
  }

  sendPlain(message) {
    if (this.closed) throw new Error('connection closed')
    const body = Buffer.from(JSON.stringify(message), 'utf8')
    if (body.length > HANDSHAKE_MAX_FRAME) throw new Error('handshake frame too large')
    const head = Buffer.allocUnsafe(4)
    head.writeUInt32BE(body.length, 0)
    this.socket.write(Buffer.concat([head, body]))
  }

  send(message) {
    if (this.closed) throw new Error('connection closed')
    if (!this.sealed) throw new Error('channel is not sealed yet')
    const body = Buffer.from(JSON.stringify(message), 'utf8')
    const sealed = aesEncrypt(this.sendKey, this.sendCounter, this.sessionId, body)
    if (sealed.length > this.maxFrame) throw new Error('frame too large')
    this.sendCounter += 1
    const head = Buffer.allocUnsafe(4)
    head.writeUInt32BE(sealed.length, 0)
    this.socket.write(Buffer.concat([head, sealed]))
  }

  installSeal({ sendKey, recvKey, sessionId }) {
    this.sendKey = toBuf(sendKey)
    this.recvKey = toBuf(recvKey)
    this.sessionId = toBuf(sessionId)
    this.sealed = true
    this.plainQueue = []
  }

  close() {
    this.fail(new Error('closed by local side'))
  }
}

function readHello(hello) {
  if (!hello || hello.t !== 'pw/hello' || hello.v !== PROTOCOL_VERSION) {
    throw new HandshakeError('bad-hello', 'unsupported peerweave greeting')
  }
  if (typeof hello.eph !== 'string' || typeof hello.id !== 'string' || typeof hello.nonce !== 'string') {
    throw new HandshakeError('bad-hello', 'greeting is missing key material')
  }
  return {
    t: 'pw/hello',
    v: PROTOCOL_VERSION,
    eph: hello.eph,
    id: hello.id,
    nonce: hello.nonce,
    name: sanitizeName(hello.name),
    instance: String(hello.instance || ''),
    listenPort: Number(hello.listenPort) || 0,
  }
}

function readChallenge(challenge) {
  if (!challenge || challenge.t !== 'pw/challenge' || challenge.v !== PROTOCOL_VERSION) {
    throw new HandshakeError('bad-challenge', 'peer rejected the link or spoke another protocol')
  }
  return {
    t: 'pw/challenge',
    v: PROTOCOL_VERSION,
    eph: String(challenge.eph || ''),
    id: String(challenge.id || ''),
    nonce: String(challenge.nonce || ''),
    name: sanitizeName(challenge.name),
    instance: String(challenge.instance || ''),
    listenPort: Number(challenge.listenPort) || 0,
    sessionId: String(challenge.sessionId || ''),
    pairAccepted: Boolean(challenge.pairAccepted),
    yourTier: Number(challenge.yourTier) || 0,
    maxFileBytes: Number(challenge.maxFileBytes) || 0,
    sharedLabel: String(challenge.sharedLabel || ''),
    sig: String(challenge.sig || ''),
  }
}

function sanitizeName(name) {
  const text = String(name || '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 80)
  return text || 'DSH peer'
}

/**
 * Joiner side. `opts`:
 *  - identity {publicRaw, privatePem}
 *  - name, instanceId, listenPort
 *  - expectedPeerRaw (Buffer, pinned from the invite or a stored peer)
 *  - pair {id, key: Buffer} for the first connection
 */
export async function runInitiatorHandshake(channel, opts) {
  const eph = generateEphemeral()
  const helloCore = readHello({
    t: 'pw/hello',
    v: PROTOCOL_VERSION,
    eph: b64u(eph.publicRaw),
    id: b64u(opts.identity.publicRaw),
    nonce: randomB64u(16),
    name: opts.name,
    instance: opts.instanceId,
    listenPort: opts.listenPort,
  })
  const digest = helloDigest(helloCore)
  const hello = { ...helloCore }
  if (opts.pair) {
    hello.pairId = String(opts.pair.id || '')
    hello.pairProof = b64u(hmacSha256(opts.pair.key, digest))
  }
  channel.sendPlain(hello)

  const rawChallenge = await channel.readPlain()
  if (rawChallenge && rawChallenge.t === 'pw/error') {
    throw new HandshakeError(rawChallenge.code || 'rejected', rawChallenge.message || 'peer rejected the link')
  }
  const challenge = readChallenge(rawChallenge)
  if (!challenge.eph || !challenge.id || !challenge.sessionId) {
    throw new HandshakeError('bad-challenge', 'peerweave peer sent an incomplete challenge')
  }
  const peerRaw = unb64u(challenge.id)
  if (opts.expectedPeerRaw && !timingSafeEq(peerRaw, opts.expectedPeerRaw)) {
    throw new HandshakeError('identity-mismatch', 'peerweave identity does not match the pinned fingerprint')
  }
  const challengeDigestValue = challengeDigest(challenge)
  const serverTranscript = domainHash('pw1/server', [digest, challengeDigestValue])
  const challengeSignature = unb64u(challenge.sig || '')
  if (!verifyWith(publicKeyOf(peerRaw), serverTranscript, challengeSignature)) {
    throw new HandshakeError('bad-signature', 'peerweave peer failed to prove its identity')
  }

  const shared = x25519Shared(eph.privateRaw, unb64u(challenge.eph))
  const salt = domainHash('pw1/salt', [digest, challengeDigestValue])
  const clientKey = hkdf32(shared, salt, 'pw1 initiator to responder')
  const serverKey = hkdf32(shared, salt, 'pw1 responder to initiator')
  const clientTranscript = domainHash('pw1/client', [digest, challengeDigestValue, shared])
  channel.sendPlain({ t: 'pw/auth', sig: b64u(signWith(opts.identity.privateKey, clientTranscript)) })

  const ready = await channel.readPlain()
  if (ready && ready.t === 'pw/error') throw new HandshakeError(ready.code || 'rejected', ready.message || 'peer rejected the link')
  if (!ready || ready.t !== 'pw/ready') throw new HandshakeError('bad-ready', 'peerweave peer did not confirm the session')
  if (!verifyWith(publicKeyOf(peerRaw), domainHash('pw1/ready', [clientTranscript]), unb64u(ready.sig || ''))) {
    throw new HandshakeError('bad-ready-signature', 'peerweave peer failed key confirmation')
  }

  channel.installSeal({ sendKey: clientKey, recvKey: serverKey, sessionId: challenge.sessionId })
  return {
    sessionId: challenge.sessionId,
    pairAccepted: challenge.pairAccepted,
    peer: {
      publicRaw: peerRaw,
      fingerprint: sha256hex(peerRaw),
      name: challenge.name,
      instanceId: challenge.instance,
      listenPort: challenge.listenPort,
      tier: challenge.yourTier,
      maxFileBytes: challenge.maxFileBytes,
      sharedLabel: challenge.sharedLabel,
      address: channel.remoteAddress,
    },
  }
}

/**
 * Inviter side. `opts`:
 *  - identity, name, instanceId, listenPort
 *  - lookupPeer(publicRaw) => { publicRaw, tier } | undefined
 *  - verifyInvite(pairId, digest, proof) => boolean
 *  - tierFor(publicRaw) => number
 *  - maxFileBytes, sharedLabel
 */
export async function runResponderHandshake(channel, opts) {
  const rawHello = await channel.readPlain()
  const hello = readHello(rawHello)
  const digest = helloDigest(hello)
  const publicRaw = unb64u(hello.id)
  const known = opts.lookupPeer(publicRaw)
  let pairAccepted = false
  if (!known) {
    if (!rawHello.pairId || !rawHello.pairProof) {
      throw new HandshakeError('unknown-peer', 'this peer is not trusted; join with an invite code first')
    }
    if (!opts.verifyInvite(String(rawHello.pairId), digest, String(rawHello.pairProof))) {
      throw new HandshakeError('bad-invite', 'the invite code is invalid, already used or expired')
    }
    pairAccepted = true
  }

  const eph = generateEphemeral()
  const sessionId = randomHex(16)
  const challengeCore = readChallenge({
    t: 'pw/challenge',
    v: PROTOCOL_VERSION,
    eph: b64u(eph.publicRaw),
    id: b64u(opts.identity.publicRaw),
    nonce: randomB64u(16),
    name: opts.name,
    instance: opts.instanceId,
    listenPort: opts.listenPort,
    sessionId,
    pairAccepted,
    yourTier: known ? opts.tierFor(publicRaw) : 0,
    maxFileBytes: opts.maxFileBytes,
    sharedLabel: opts.sharedLabel,
  })
  const challengeDigestValue = challengeDigest(challengeCore)
  const serverTranscript = domainHash('pw1/server', [digest, challengeDigestValue])
  channel.sendPlain({ ...challengeCore, sig: b64u(signWith(opts.identity.privateKey, serverTranscript)) })

  const auth = await channel.readPlain()
  if (!auth || auth.t !== 'pw/auth') throw new HandshakeError('bad-auth', 'peerweave peer did not authenticate')
  const shared = x25519Shared(eph.privateRaw, unb64u(hello.eph))
  const clientTranscript = domainHash('pw1/client', [digest, challengeDigestValue, shared])
  if (!verifyWith(publicKeyOf(publicRaw), clientTranscript, unb64u(auth.sig || ''))) {
    throw new HandshakeError('bad-auth-signature', 'peerweave peer failed to prove possession of its key')
  }
  const salt = domainHash('pw1/salt', [digest, challengeDigestValue])
  const clientKey = hkdf32(shared, salt, 'pw1 initiator to responder')
  const serverKey = hkdf32(shared, salt, 'pw1 responder to initiator')
  channel.sendPlain({ t: 'pw/ready', sig: b64u(signWith(opts.identity.privateKey, domainHash('pw1/ready', [clientTranscript]))) })
  channel.installSeal({ sendKey: serverKey, recvKey: clientKey, sessionId })

  return {
    sessionId,
    pairAccepted,
    inviteId: pairAccepted ? String(rawHello.pairId) : '',
    peer: {
      publicRaw,
      fingerprint: sha256hex(publicRaw),
      name: hello.name,
      instanceId: hello.instance,
      listenPort: hello.listenPort,
      tier: known ? opts.tierFor(publicRaw) : 0,
      address: channel.remoteAddress,
    },
  }
}

/** Import a raw Ed25519 public key without leaking the DER helper into callers. */
const publicKeyCache = new Map()
function publicKeyOf(raw) {
  const key = b64u(raw)
  let value = publicKeyCache.get(key)
  if (!value) {
    value = publicKeyFromRaw(raw)
    if (publicKeyCache.size > 256) publicKeyCache.clear()
    publicKeyCache.set(key, value)
  }
  return value
}
