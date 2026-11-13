/**
 * Agent tools. All four are read/communicate operations allowed by the remote
 * side's grant; changing permissions stays a user-only action in the UI.
 */
function textResult(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return [{ type: 'text', text }]
}

function schema(properties, required = []) {
  return { type: 'object', properties, required, additionalProperties: false }
}

function renderJson(args, value) {
  return textResult(value)
}

function resolvePeerId(service, input) {
  const text = String(input || '').trim()
  if (!text) throw new Error('peerId is required')
  const peers = service.store.peers()
  const exact = peers.find((peer) => peer.id === text)
  if (exact) return exact.id
  const byPrefix = peers.filter((peer) => peer.id.startsWith(text.toLowerCase()))
  if (byPrefix.length === 1) return byPrefix[0].id
  const byName = peers.filter((peer) => peer.name.toLowerCase() === text.toLowerCase())
  if (byName.length === 1) return byName[0].id
  throw new Error(`no unique peer matches "${text}"; call peerweave_peers for the peer list`)
}

function assertUnlocked(service) {
  if (!service.identity) {
    throw new Error('Peerweave is locked. Ask the user to open Settings → Peerweave and unlock it with the install password.')
  }
}

export function registerTools(c, service) {
  const disposers = []

  disposers.push(
    c.tools.register({
      name: 'peerweave_peers',
      description:
        'List the DSH peers this machine is linked to, with connection state, the access this machine grants them, and the access they grant this machine. Peerweave must be unlocked by the user.',
      parameters: schema({}),
      output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
      async execute() {
        assertUnlocked(service)
        return { peers: service.publicState().peers, listening: service.publicState().listening }
      },
    }),
  )

  disposers.push(
    c.tools.register({
      name: 'peerweave_history',
      description:
        'Read a remote DSH peer\'s session history across all of its workspaces. Without sessionId it lists workspaces and sessions; with sessionId it returns that session\'s messages. Requires the peer to grant tier 1 (history) or higher to this machine.',
      parameters: schema(
        {
          peerId: { type: 'string', description: 'Peer fingerprint or unique peer name.' },
          sessionId: { type: 'string', description: 'Optional session id from the listing.' },
        },
        ['peerId'],
      ),
      output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
      async execute(args) {
        assertUnlocked(service)
        const peerId = resolvePeerId(service, args && args.peerId)
        if (args && args.sessionId) {
          return service.remoteCall(peerId, 'history.read', { sessionId: String(args.sessionId) }, 30000)
        }
        return service.remoteCall(peerId, 'history.list', {}, 20000)
      },
    }),
  )

  disposers.push(
    c.tools.register({
      name: 'peerweave_read_file',
      description:
        'Read one file from a remote DSH peer workspace. Read-only: it never writes to the peer. First call with only peerId to list workspaces, then pass the workspace id or title. Requires the peer to grant tier 2 (files) or higher, and the file must fit the size limit the peer set.',
      parameters: schema(
        {
          peerId: { type: 'string', description: 'Peer fingerprint or unique peer name.' },
          path: { type: 'string', description: 'Path relative to the selected workspace root.' },
          workspace: { type: 'string', description: 'Workspace id or title; optional when the peer has exactly one workspace.' },
        },
        ['peerId', 'path'],
      ),
      output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
      async execute(args) {
        assertUnlocked(service)
        const peerId = resolvePeerId(service, args && args.peerId)
        const path = String((args && args.path) || '')
        const requested = String((args && args.workspace) || '').trim()
        let workspaceId = ''
        if (requested) {
          const listing = await service.remoteCall(peerId, 'files.workspaces', {}, 20000)
          const workspaces = (listing && listing.workspaces) || []
          const found = workspaces.find((entry) => entry.id === requested)
            || workspaces.find((entry) => entry.title.toLowerCase() === requested.toLowerCase())
          if (!found) throw new Error(`unknown workspace "${requested}"; available: ${workspaces.map((entry) => entry.title).join(', ')}`)
          workspaceId = found.id
        } else {
          const listing = await service.remoteCall(peerId, 'files.workspaces', {}, 20000)
          const workspaces = (listing && listing.workspaces) || []
          if (workspaces.length === 1) workspaceId = workspaces[0].id
          else if (workspaces.length > 1) {
            throw new Error(`the peer has multiple workspaces; pass workspace= one of: ${workspaces.map((entry) => entry.title).join(', ')}`)
          }
        }
        return service.remoteCall(peerId, 'files.read', { path, workspaceId }, 30000)
      },
    }),
  )

  disposers.push(
    c.tools.register({
      name: 'peerweave_chat',
      description:
        'Send a message to a remote DSH peer\'s own agent and return its answer. Requires the peer to grant tier 3 (chat) to this machine; the peer sees this as a message from its linked peer.',
      parameters: schema(
        {
          peerId: { type: 'string', description: 'Peer fingerprint or unique peer name.' },
          message: { type: 'string', description: 'Message text, at most 4000 characters.' },
        },
        ['peerId', 'message'],
      ),
      output: { schema: { type: 'object', additionalProperties: true }, render: renderJson },
      async execute(args) {
        assertUnlocked(service)
        const peerId = resolvePeerId(service, args && args.peerId)
        return service.remoteCall(peerId, 'chat.send', { text: String((args && args.message) || '') }, 120000)
      },
    }),
  )

  return () => {
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        /* ignore */
      }
    }
  }
}
