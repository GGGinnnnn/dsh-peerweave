/**
 * Host half of dsh-peerweave.
 *
 * The service owns the encrypted peer listener, the password vault and the
 * tiered operations. This file only wires the service into the Harness: the
 * same-origin management API for the Client page, and the four read-only agent
 * tools. Permission changes remain user-only actions in the UI.
 *
 * Activation is defensive on purpose: a plugin failure must never fail the
 * whole web boot. Every registration is contained, and optional services are
 * read with `ctx.get` instead of declared as hard dependencies.
 */
import { PeerweaveService } from './lib/service.js'
import { createApiHandler } from './lib/api.js'
import { registerTools } from './lib/tools.js'

export const name = 'peerweave'

export function apply(ctx, config = {}) {
  try {
    applyInner(ctx, config)
  } catch (error) {
    try {
      ctx.logger?.error?.(`[peerweave] activation failed: ${error && error.stack ? error.stack : error}`)
    } catch {
      /* logging must never throw */
    }
  }
}

function applyInner(ctx, config) {
  const service = new PeerweaveService({
    ctx,
    config,
    log: (message) => {
      try {
        ctx.logger?.info?.(`[peerweave] ${message}`)
      } catch {
        /* ignore */
      }
    },
  })

  service.ready.catch((error) => {
    try {
      ctx.logger?.error?.(`[peerweave] state load failed: ${error && error.stack ? error.stack : error}`)
    } catch {
      /* ignore */
    }
  })

  try {
    ctx.effect(
      () => () => {
        service.dispose()
      },
      'peerweave: lifecycle',
    )
  } catch (error) {
    ctx.logger?.error?.(`[peerweave] lifecycle registration failed: ${error}`)
  }

  // Core services only. `workspaceRegistry` is optional: it enriches workspace
  // titles and enables guest-session cleanup, but history still works by cwd.
  ctx.inject(
    ['webServer', 'tools', 'sessionController', 'sessionQuery', 'workingDirectory'],
    (c) => {
      try {
        service.attach({
          controller: c.sessionController,
          query: c.sessionQuery,
          workingDirectory: c.workingDirectory,
          registry: typeof c.get === 'function' ? c.get('workspaceRegistry') : undefined,
        })
      } catch (error) {
        c.logger?.error?.(`[peerweave] dependency attach failed: ${error}`)
      }

      try {
        const handler = createApiHandler(service)
        c.effect(
          () => c.webServer.register({ kind: 'prefix', path: '/peerweave', handler }),
          'peerweave: management api',
        )
      } catch (error) {
        c.logger?.error?.(`[peerweave] API registration failed: ${error}`)
      }

      try {
        c.effect(() => registerTools(c, service), 'peerweave: tools')
      } catch (error) {
        c.logger?.error?.(`[peerweave] tool registration failed: ${error}`)
      }

      c.logger?.info?.('[peerweave] management api and tools registered')
    },
  )
}
