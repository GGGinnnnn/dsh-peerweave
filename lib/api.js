/**
 * Same-origin management API for the Peerweave settings page and dock.
 *
 * Routes are registered on the local web server, outside the shell's index
 * authentication, so every request is fenced here: loopback Host, same-origin
 * Origin, an explicit x-peerweave header (forces a CORS preflight elsewhere),
 * and a password-issued in-memory token for everything except setup/unlock.
 */
import { errorText, isLoopbackHostname } from './util.js'

const PREFIX = '/peerweave/'
const MAX_BODY = 1024 * 1024

function sendJson(res, status, payload) {
  let text
  try {
    text = JSON.stringify(payload)
  } catch {
    text = JSON.stringify({ ok: false, error: { code: 'serialize', message: 'response could not be serialized' } })
    status = 500
  }
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-length': Buffer.byteLength(text),
  })
  res.end(text)
}

function failure(code, message) {
  return { ok: false, error: { code, message: message || code } }
}

function statusFor(code) {
  switch (code) {
    case 'locked':
    case 'not-configured':
    case 'bad-password':
    case 'locked-out':
    case 'token-required':
      return 401
    case 'permission-denied':
      return 403
    case 'unknown-peer':
    case 'not-found':
      return 404
    case 'file-too-large':
      return 413
    case 'rate-limited':
      return 429
    case 'grant-expired':
    case 'grant-mismatch':
    case 'confirm-too-early':
    case 'recover-expired':
    case 'already-connected':
    case 'busy':
      return 409
    default:
      return 400
  }
}

function readBody(req) {
  return new Promise((resolvePromise, rejectPromise) => {
    let raw = ''
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY) {
        rejectPromise(new Error('request body is too large'))
        req.destroy()
        return
      }
      raw += chunk
    })
    req.on('end', () => {
      if (!raw) {
        resolvePromise({})
        return
      }
      try {
        resolvePromise(JSON.parse(raw))
      } catch {
        rejectPromise(new Error('request body must be JSON'))
      }
    })
    req.on('error', rejectPromise)
  })
}

export function createApiHandler(service) {
  function fence(req, res) {
    const hostHeader = String(req.headers.host || '')
    let hostname = ''
    try {
      hostname = new URL(`http://${hostHeader}`).hostname
    } catch {
      sendJson(res, 403, failure('forbidden-host', 'a valid Host header is required'))
      return false
    }
    const trusted = Array.isArray(service.config.trustedHosts) ? service.config.trustedHosts.map(String) : []
    if (!isLoopbackHostname(hostname) && !trusted.includes(hostname) && !trusted.includes(hostHeader.toLowerCase())) {
      sendJson(res, 403, failure('forbidden-host', 'Peerweave management only answers on loopback hosts'))
      return false
    }
    const origin = req.headers.origin
    if (origin) {
      try {
        if (new URL(origin).host.toLowerCase() !== hostHeader.toLowerCase()) {
          sendJson(res, 403, failure('forbidden-origin', 'cross-origin requests are refused'))
          return false
        }
      } catch {
        sendJson(res, 403, failure('forbidden-origin', 'a malformed Origin header is refused'))
        return false
      }
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      sendJson(res, 403, failure('forbidden-origin', 'cross-site requests are refused'))
      return false
    }
    if (req.headers['x-peerweave'] !== '1') {
      sendJson(res, 403, failure('missing-header', 'the x-peerweave request header is required'))
      return false
    }
    return true
  }

  return async function handler(req, res) {
    try {
      if (!fence(req, res)) return
      const method = String(req.method || 'GET').toUpperCase()
      const url = new URL(String(req.url || '/'), 'http://placeholder')
      const path = url.pathname

      if (path === '/peerweave/public') {
        if (method !== 'GET') return sendJson(res, 405, failure('method-not-allowed', 'use GET'))
        await service.ready
        return sendJson(res, 200, { ok: true, data: service.publicState() })
      }

      if (!path.startsWith(PREFIX)) return sendJson(res, 404, failure('not-found', 'unknown Peerweave route'))
      if (method !== 'POST') return sendJson(res, 405, failure('method-not-allowed', 'use POST'))

      const action = path.slice(PREFIX.length)
      const body = await readBody(req)
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return sendJson(res, 400, failure('bad-request', 'a JSON object body is required'))
      }
      const ip = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : 'local'
      const token = req.headers['x-peerweave-token']
      const openActions = new Set(['setup', 'unlock', 'recover/prepare', 'recover/commit'])
      if (!openActions.has(action) && !service.checkToken(token, ip)) {
        return sendJson(res, 401, failure('token-required', 'unlock Peerweave with the password first'))
      }
      await service.ready

      const result = await dispatch(service, action, body, ip)
      return sendJson(res, 200, { ok: true, data: result })
    } catch (error) {
      const code = (error && error.code) || 'error'
      const status = code === 'error' ? 500 : statusFor(code)
      if (status >= 500) service.log('api error: ' + errorText(error))
      return sendJson(res, status, failure(code, errorText(error)))
    }
  }
}

async function dispatch(service, action, body, ip) {
  switch (action) {
    case 'setup': {
      if (body.password !== body.confirm) throw Object.assign(new Error('the two passwords do not match'), { code: 'password-mismatch' })
      return service.setup(body.password, body.displayName, ip)
    }
    case 'unlock':
      return service.unlock(body.password, ip)
    case 'lock':
      service.lock()
      return { locked: true }
    case 'reset':
      return service.reset(body.password, ip)
    case 'recover/prepare':
      return service.forceResetPrepare(ip)
    case 'recover/commit':
      return service.forceResetCommit(body.nonce, body.confirm, ip)
    case 'password/change':
      if (body.nextPassword !== body.confirm) throw Object.assign(new Error('the two new passwords do not match'), { code: 'password-mismatch' })
      return service.changePassword(body.currentPassword, body.nextPassword, ip)
    case 'invite/create':
      return service.createInvite(body.password, ip, { mode: body.mode })
    case 'invite/accept':
      return service.acceptInvite(
        {
          code: body.code,
          transport: body.transport,
          sshTarget: body.sshTarget,
          sshRemotePort: body.sshRemotePort,
          dialHost: body.dialHost,
          dialPort: body.dialPort,
        },
        ip,
      )
    case 'peer/connect':
      return { peer: await service.connectPeer(String(body.peerId || '')) }
    case 'peer/disconnect':
      return service.disconnectPeer(String(body.peerId || ''))
    case 'peer/remove':
      return service.removePeer(String(body.peerId || ''), body.password, ip)
    case 'permission/prepare':
      return service.prepareGrant(String(body.peerId || ''), body.tier, body.password, ip)
    case 'permission/commit':
      return service.commitGrant(String(body.peerId || ''), body.tier, body.nonce, body.password, ip)
    case 'settings/update':
      return service.updateSettings(body.patch && typeof body.patch === 'object' ? body.patch : {}, body.password, ip)
    case 'settings/read':
      return service.fullSettings()
    case 'remote/history/list':
      return service.remoteCall(String(body.peerId || ''), 'history.list', {}, 20000)
    case 'remote/history/read':
      return service.remoteCall(String(body.peerId || ''), 'history.read', { sessionId: body.sessionId }, 30000)
    case 'remote/files/list':
      return service.remoteCall(String(body.peerId || ''), 'files.list', { path: String(body.path || ''), workspaceId: body.workspaceId }, 20000)
    case 'remote/files/workspaces':
      return service.remoteCall(String(body.peerId || ''), 'files.workspaces', {}, 20000)
    case 'remote/files/read':
      return service.remoteCall(String(body.peerId || ''), 'files.read', { path: String(body.path || ''), workspaceId: body.workspaceId }, 30000)
    case 'remote/copy':
      return service.copyFromPeer(String(body.peerId || ''), String(body.path || ''), body.workspaceId)
    case 'remote/chat':
      return service.remoteCall(String(body.peerId || ''), 'chat.send', { text: String(body.message || '') }, 120000)
    default:
      throw Object.assign(new Error(`unknown Peerweave action: ${action}`), { code: 'bad-request' })
  }
}
