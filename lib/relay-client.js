/**
 * Client side of the Peerweave relay rendezvous.
 *
 * `openRelay` sends the room header and exposes `waitForPair()`; once the relay
 * answers OK, call `takeResidual()` and hand the socket to SecureChannel.
 */
import net from 'node:net'

const MAX_HEADER = 512

function lineReader(socket) {
  let buffer = Buffer.alloc(0)
  const lines = []
  let waiter = null
  let closedError = null

  const settle = (error, line) => {
    if (!waiter) return
    const current = waiter
    waiter = null
    clearTimeout(current.timer)
    if (error) current.reject(error)
    else current.resolve(line)
  }

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    if (buffer.length > MAX_HEADER * 4) {
      settle(new Error('relay header is too large'))
      socket.destroy()
      return
    }
    for (;;) {
      const index = buffer.indexOf(0x0a)
      if (index < 0) return
      const line = buffer.subarray(0, index).toString('utf8').trim()
      buffer = buffer.subarray(index + 1)
      if (waiter) settle(null, line)
      else lines.push(line)
    }
  }
  const onError = (error) => {
    closedError = error
    settle(error)
  }
  socket.on('data', onData)
  socket.once('error', onError)

  return {
    next(timeoutMs, label) {
      if (lines.length > 0) return Promise.resolve(lines.shift())
      if (closedError) return Promise.reject(closedError)
      return new Promise((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          waiter = null
          socket.destroy()
          rejectPromise(Object.assign(new Error(`${label || 'relay'} timed out`), { code: 'relay-timeout' }))
        }, timeoutMs)
        timer.unref?.()
        waiter = { resolve: resolvePromise, reject: rejectPromise, timer }
      })
    },
    take() {
      socket.off('data', onData)
      socket.off('error', onError)
      socket.pause()
      return buffer
    },
  }
}

export async function openRelay(options) {
  const host = String(options.host || '')
  const port = Number(options.port) || 41338
  const room = String(options.room || '')
  const role = options.role === 'host' ? 'host' : 'join'
  const token = String(options.token || '')
  const waitForPeer = options.waitForPeer !== false
  const waitTimeoutMs = Number(options.waitTimeoutMs) || 120000
  const connectTimeoutMs = Number(options.connectTimeoutMs) || 10000

  const socket = await new Promise((resolvePromise, rejectPromise) => {
    const client = net.connect({ host, port })
    client.setNoDelay(true)
    const timer = setTimeout(() => {
      client.destroy()
      rejectPromise(Object.assign(new Error(`relay ${host}:${port} connect timed out`), { code: 'relay-connect-timeout' }))
    }, connectTimeoutMs)
    timer.unref?.()
    client.once('connect', () => {
      clearTimeout(timer)
      client.off('error', onError)
      resolvePromise(client)
    })
    const onError = (error) => {
      clearTimeout(timer)
      client.destroy()
      rejectPromise(Object.assign(new Error(`relay ${host}:${port} — ${error.message}`), { code: 'relay-connect-failed' }))
    }
    client.once('error', onError)
  })

  socket.write(`PWRELAY 1 ${room} ${role} ${token || '-'}\n`)
  const reader = lineReader(socket)
  let paired = false
  let residual = null

  const readPair = async () => {
    for (;;) {
      const line = await reader.next(waitTimeoutMs, 'relay pairing')
      if (line === 'OK') {
        paired = true
        return
      }
      if (line === 'WAIT') continue
      if (line.startsWith('ERR')) {
        const code = line.slice(4).trim() || 'relay-error'
        socket.destroy()
        throw Object.assign(new Error(`relay rejected the room: ${code}`), { code })
      }
      throw Object.assign(new Error(`unexpected relay line: ${line.slice(0, 60)}`), { code: 'relay-protocol' })
    }
  }

  try {
    if (waitForPeer) {
      await readPair()
      residual = reader.take()
    } else {
      const first = await reader.next(waitTimeoutMs, 'relay room')
      if (first === 'OK') {
        paired = true
        residual = reader.take()
      } else if (first === 'WAIT') {
        // keep the reader active; waitForPair() consumes the OK
      } else if (first.startsWith('ERR')) {
        const code = first.slice(4).trim() || 'relay-error'
        socket.destroy()
        throw Object.assign(new Error(`relay rejected the room: ${code}`), { code })
      } else {
        throw Object.assign(new Error(`unexpected relay line: ${first.slice(0, 60)}`), { code: 'relay-protocol' })
      }
    }
  } catch (error) {
    try {
      socket.destroy()
    } catch {
      /* ignore */
    }
    throw error
  }

  return {
    socket,
    role,
    room,
    paired,
    async waitForPair() {
      if (!paired) await readPair()
      if (residual === null) residual = reader.take()
      return { socket, residual }
    },
    takeResidual() {
      if (residual === null) residual = reader.take()
      return residual
    },
    close() {
      try {
        socket.destroy()
      } catch {
        /* ignore */
      }
    },
  }
}
