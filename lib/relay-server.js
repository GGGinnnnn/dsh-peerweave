/**
 * Peerweave relay server.
 *
 * A deliberately dumb TCP rendezvous: two peers connect outbound to the same
 * room with the roles `host` and `join`; after both are present the server
 * pipes bytes verbatim. Peerweave's own end-to-end handshake runs over that
 * pipe, so the relay never sees plaintext and cannot impersonate either side.
 *
 * Wire protocol (single line before piping):
 *   client -> relay: PWRELAY 1 <room> <role> <token>\n
 *   relay -> client: WAIT\n            (room accepted, waiting for the other role)
 *                    OK\n              (paired; raw bytes follow)
 *                    ERR <code>\n      (rejected; socket closes)
 *
 * Run it on a public VPS:
 *   node relay.js --port 41338 --token <shared-secret>
 */
import net from 'node:net'
import { timingSafeEqual } from 'node:crypto'

const MAX_HEADER = 512
const ROOM_RE = /^[a-f0-9]{16,64}$/i
const ROLES = new Set(['host', 'join'])

function safeEqual(left, right) {
  const a = Buffer.from(String(left))
  const b = Buffer.from(String(right))
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

export function startRelayServer(options = {}) {
  const host = String(options.host || '0.0.0.0')
  const port = options.port === 0 ? 0 : Number(options.port) || 41338
  const token = String(options.token || '')
  const maxRooms = Number(options.maxRooms) || 1000
  const idleMs = Number(options.idleMs) || 120000
  const log = typeof options.log === 'function' ? options.log : () => {}
  const rooms = new Map()
  const sockets = new Set()

  function send(socket, line) {
    try {
      socket.write(`${line}\n`)
    } catch {
      /* ignore */
    }
  }

  function reject(socket, code) {
    send(socket, `ERR ${code}`)
    try {
      socket.end()
    } catch {
      /* ignore */
    }
    setTimeout(() => socket.destroy(), 200)
  }

  function cleanupRoom(room) {
    const entry = rooms.get(room)
    if (!entry) return
    if (entry.timer) clearTimeout(entry.timer)
    rooms.delete(room)
  }

  function pair(entry) {
    const { hostSocket, joinSocket, hostResidual, joinResidual } = entry
    cleanupRoom(entry.room)
    for (const [socket, other, residual] of [
      [hostSocket, joinSocket, joinResidual],
      [joinSocket, hostSocket, hostResidual],
    ]) {
      if (!socket || socket.destroyed || !other || other.destroyed) {
        const alive = socket && !socket.destroyed ? socket : other
        if (alive) reject(alive, 'peer-left')
        return
      }
      send(socket, 'OK')
    }
    const link = (left, right, residual) => {
      left.on('error', () => right.destroy())
      left.on('close', () => right.destroy())
      if (residual && residual.length > 0) right.write(residual)
      left.pipe(right)
    }
    link(hostSocket, joinSocket, hostResidual)
    link(joinSocket, hostSocket, joinResidual)
    log(`relay: room ${entry.room.slice(0, 8)}… paired`)
  }

  function handle(socket) {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.setNoDelay(true)
    socket.setTimeout(idleMs)
    let buffer = Buffer.alloc(0)
    let room = null
    let role = null

    const onTimeout = () => {
      if (!room) {
        socket.destroy()
        return
      }
      const entry = rooms.get(room)
      if (entry) {
        const other = role === 'host' ? entry.joinSocket : entry.hostSocket
        if (other) reject(other, 'timeout')
      }
      reject(socket, 'timeout')
      cleanupRoom(room)
    }
    socket.once('timeout', onTimeout)

    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length > MAX_HEADER) {
        socket.destroy()
        return
      }
      const index = buffer.indexOf(0x0a)
      if (index < 0) return
      const line = buffer.subarray(0, index).toString('utf8').trim()
      const residual = buffer.subarray(index + 1)
      socket.off('data', onData)
      const parts = line.split(/\s+/)
      if (parts.length !== 5 || parts[0] !== 'PWRELAY' || parts[1] !== '1') {
        reject(socket, 'bad-header')
        return
      }
      room = parts[2].toLowerCase()
      role = parts[3]
      const clientToken = parts[4] === '-' ? '' : parts[4]
      if (!ROOM_RE.test(room) || !ROLES.has(role)) {
        reject(socket, 'bad-header')
        return
      }
      if (token && !safeEqual(clientToken, token)) {
        reject(socket, 'unauthorized')
        return
      }
      if (!rooms.has(room)) {
        if (rooms.size >= maxRooms) {
          reject(socket, 'busy')
          return
        }
        rooms.set(room, {
          room,
          hostSocket: null,
          joinSocket: null,
          hostResidual: null,
          joinResidual: null,
          timer: null,
        })
      }
      const entry = rooms.get(room)
      if (role === 'host') {
        if (entry.hostSocket) {
          reject(socket, 'role-taken')
          return
        }
        entry.hostSocket = socket
        entry.hostResidual = residual
      } else {
        if (entry.joinSocket) {
          reject(socket, 'role-taken')
          return
        }
        entry.joinSocket = socket
        entry.joinResidual = residual
      }
      socket.off('timeout', onTimeout)
      send(socket, 'WAIT')
      socket.on('close', () => {
        const current = rooms.get(room)
        if (!current) return
        if (role === 'host' && current.hostSocket === socket) current.hostSocket = null
        if (role === 'join' && current.joinSocket === socket) current.joinSocket = null
        const other = role === 'host' ? current.joinSocket : current.hostSocket
        if (other) reject(other, 'peer-left')
        cleanupRoom(room)
      })
      if (entry.hostSocket && entry.joinSocket) {
        clearTimeout(entry.timer)
        pair(entry)
      } else {
        entry.timer = setTimeout(() => {
          const other = role === 'host' ? entry.joinSocket : entry.hostSocket
          if (other) reject(other, 'timeout')
          reject(socket, 'timeout')
          cleanupRoom(room)
        }, idleMs)
        entry.timer.unref?.()
      }
    }
    socket.on('data', onData)
  }

  return new Promise((resolvePromise, rejectPromise) => {
    const server = net.createServer(handle)
    const onError = (error) => {
      server.off('listening', onListening)
      rejectPromise(error)
    }
    const onListening = () => {
      server.off('error', onError)
      server.on('error', (error) => log(`relay server error: ${error.message}`))
      const address = server.address()
      resolvePromise({
        server,
        port: address && typeof address === 'object' ? address.port : port,
        close: () =>
          new Promise((done) => {
            for (const socket of sockets) socket.destroy()
            sockets.clear()
            rooms.clear()
            server.close(() => done())
          }),
      })
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen({ port, host })
  })
}
