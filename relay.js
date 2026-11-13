#!/usr/bin/env node
/**
 * Stand-alone Peerweave relay for a public VPS.
 *
 *   node relay.js --port 41338 --token <shared-secret>
 *   node relay.js --host 0.0.0.0 --port 41338 --token secret
 *
 * It pairs one `host` and one `join` connection per room and then forwards
 * bytes verbatim; Peerweave's end-to-end handshake authenticates the peers.
 */
import { startRelayServer } from './lib/relay-server.js'

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
if (args.help) {
  console.log('Usage: node relay.js [--host 0.0.0.0] [--port 41338] [--token SECRET]')
  process.exit(0)
}

const port = Number(args.port) || 41338
const host = String(args.host || '0.0.0.0')
const token = String(args.token || '')

const relay = await startRelayServer({
  host,
  port,
  token,
  log: (message) => console.log(`[relay] ${message}`),
})
console.log(`[relay] listening on ${host}:${relay.port}${token ? ' (token required)' : ''}`)

const shutdown = async () => {
  await relay.close()
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
