/**
 * Host half of dsh-peerweave.
 *
 * The service owns the encrypted peer listener, the password vault and the
 * tiered operations. This file only wires the service into the Harness: the
 * same-origin management API for the Client page, and the four read-only agent
 * tools. Permission changes remain user-only actions in the UI.
 */
import { PeerweaveService } from './lib/service.js'
import { createApiHandler } from './lib/api.js'
import { registerTools } from './lib/tools.js'

export const name = 'peerweave'

export function apply(ctx, config = {}) {
  const service = new PeerweaveService({
    ctx,
    config,
    log: (message) => {
      try {
        ctx.logger?.info?.(`[peerweave] ${message}`)
      } catch {
        /* logging must never break the plugin */
      }
    },
  })

  ctx.effect(
    () => () => {
      service.dispose()
    },
    'peerweave: lifecycle',
  )

  // The peer service itself needs no Harness service to hold state or to listen;
  // history and chat need the session services, and the UI needs the web server.
  ctx.inject(
    ['webServer', 'tools', 'sessionController', 'sessionQuery', 'workingDirectory', 'workspaceRegistry'],
    (c) => {
      service.attach({
        controller: c.sessionController,
        query: c.sessionQuery,
        workingDirectory: c.workingDirectory,
        registry: c.workspaceRegistry,
      })
      const handler = createApiHandler(service)
      const disposeRoute = c.effect(
        () => c.webServer.register({ kind: 'prefix', path: '/peerweave', handler }),
        'peerweave: management api',
      )
      const disposeTools = c.effect(() => registerTools(c, service), 'peerweave: tools')
      c.logger?.info?.('[peerweave] management api and tools registered')
      return () => {
        try {
          disposeRoute()
        } catch {
          /* ignore */
        }
        try {
          disposeTools()
        } catch {
          /* ignore */
        }
      }
    },
  )
}
