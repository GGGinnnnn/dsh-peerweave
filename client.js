window.__ModuleLoader__.load({
  id: 'dsh-peerweave',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useRef, useCallback } = React

    const NS = 'peerweave'
    const API = '/peerweave'
    const MI_B = 1024 * 1024

    // ------------------------------------------------------------------
    // Locale dictionaries
    // ------------------------------------------------------------------
    const EN = {
      'section.title': 'Peerweave',
      'section.description': 'Encrypted links to DSH instances on other computers.',
      'dock.title': 'Peerweave',
      'dock.setupChip': 'Set up Peerweave',
      'status.connected': 'Connected',
      'status.offline': 'Offline',
      'status.locked': 'Locked',
      'status.inbound': 'inbound',
      'status.outbound': 'outbound',
      'tier.0': 'Only linked',
      'tier.1': 'View workspace',
      'tier.2': 'Read files',
      'tier.3': 'Chat with DSH',
      'tier.unknown': 'Unknown',
      'tier.short.0': 'linked',
      'tier.short.1': 'view',
      'tier.short.2': 'files',
      'tier.short.3': 'chat',
      'common.password': 'Password',
      'common.confirm': 'Confirm',
      'common.cancel': 'Cancel',
      'common.save': 'Save',
      'common.copy': 'Copy',
      'common.copied': 'Copied',
      'common.close': 'Close',
      'common.loading': 'Loading…',
      'common.none': 'None',
      'common.bytes': 'bytes',
      'common.time': 'Time',
      'common.refresh': 'Refresh',
      'setup.title': 'Create the Peerweave password',
      'setup.intro': 'Peerweave encrypts the link and seals this machine’s identity key with a password. Set the password now; every permission change asks for it again.',
      'setup.password': 'New password (at least 8 characters)',
      'setup.confirm': 'Repeat the password',
      'setup.displayName': 'Display name (optional)',
      'setup.submit': 'Create vault',
      'setup.tooShort': 'Use at least 8 characters.',
      'setup.mismatch': 'The two passwords do not match.',
      'setup.done': 'Vault created. Keep the password safe: losing it means re-pairing every peer.',
      'unlock.title': 'Unlock Peerweave',
      'unlock.intro': 'Enter the install password to decrypt the identity key and use peer links.',
      'unlock.submit': 'Unlock',
      'recover.title': 'Forgot the password?',
      'recover.intro': 'Force-clearing returns Peerweave to its first-run state and deletes the identity key, the password, every peer and all settings.',
      'recover.action': 'Force-clear Peerweave…',
      'recover.start': 'Start the 10-second confirmation',
      'recover.wait': 'Confirm unlocks in {0}s',
      'recover.confirm': 'Erase everything',
      'recover.cancel': 'Cancel',
      'recover.warning': 'This cannot be undone. Only use it when the password is lost.',
      'recover.done': 'Peerweave was cleared. Create a new password.',
      'peers.title': 'Peers',
      'peers.empty': 'No peers yet. Create an invite here, then join it from the other computer.',
      'peers.fingerprint': 'Fingerprint',
      'peers.grantedByMe': 'They may do this here',
      'peers.grantedToMe': 'I may do this there',
      'peers.connect': 'Connect',
      'peers.disconnect': 'Disconnect',
      'peers.remove': 'Forget peer',
      'peers.removeConfirm': 'Forget this peer? This deletes the trust record on this machine.',
      'peers.lastSeen': 'Last seen',
      'peers.guest': 'guest session',
      'peers.transport': 'Transport',
      'grant.title': 'Access I grant them',
      'grant.review': 'Review change',
      'grant.confirm': 'Confirm change',
      'grant.wait': 'Confirm unlocks in {0}s',
      'grant.applied': 'Permission updated.',
      'grant.needsPassword': 'Enter the password to change permissions.',
      'grant.warning':
        'Tier 3 gives the remote peer control over a DSH agent on this computer. That agent can read files, run commands and use every tool this workspace allows. Only grant this to someone you fully trust, and confirm only after the 10-second delay.',
      'invite.title': 'Invites',
      'invite.intro': 'An invite code carries this machine’s address, fingerprint and a single-use pairing secret. Send it over a channel you trust.',
      'invite.create': 'Create invite code',
      'invite.created': 'Invite created. It expires in 10 minutes and works once.',
      'invite.join': 'Join another DSH',
      'invite.code': 'Invite code',
      'invite.joinSubmit': 'Join with code',
      'invite.ssh': 'Use an SSH tunnel',
      'invite.sshTarget': 'SSH target (user@host)',
      'invite.sshPort': 'Peer listen port on the SSH host',
      'settings.title': 'Sharing settings',
      'settings.maxFile': 'Largest file others may read (MiB)',
      'settings.maxFileHint': 'Applies to every peer with tier 2 or higher. Hard cap: 2048 MiB (2 GiB).',
      'tutorial.lan.title': 'LAN direct',
      'tutorial.lan.body': 'Use when both computers are on the same LAN.\n1. Unlock Peerweave on both sides and set the password.\n2. A: keep the listen address IPv4 (0.0.0.0) and port 41337.\n3. A: leave "Address peers should dial" empty to use the detected LAN IPv4.\n4. A: create a Direct invite and send it to B.\n5. B: paste the invite and join. If it fails, allow TCP 41337 in A’s firewall.\n6. After pairing, set the tier each side grants.',
      'tutorial.portForward.title': 'Public IPv4 + port forwarding',
      'tutorial.portForward.body': 'Use when A has a public IPv4 address or a DDNS name.\n1. Forward TCP 41337 on the router to A’s LAN IP:41337 and allow it in the host firewall.\n2. A: set "Address peers should dial" to the public IP or DDNS name.\n3. A: create a Direct invite; B joins from any network.\n4. Test from a phone hotspot or another network.\nIf the router WAN address differs from the public IP (CGNAT), port forwarding cannot work; use Tailscale, a relay, or reverse SSH.',
      'tutorial.customDial.title': 'Custom dial host/port',
      'tutorial.customDial.body': 'Use when the advertised address is unreachable, or the outside port differs from the listen port.\n1. Prepare the path first: ngrok tcp 41337, frp, a reverse SSH tunnel, or a port forward.\n2. A: create a Direct invite normally.\n3. B: when joining, fill "Custom dial host/port" with the real endpoint, for example abc.tcp.ngrok.io and 12345.\n4. Leave the fields empty to use the invite address.\nOnly the dial target changes; the invite fingerprint still authenticates A. The custom address is saved for reconnects.',
      'tutorial.reverseSsh.title': 'Reverse SSH (A behind NAT)',
      'tutorial.reverseSsh.body': 'Use when A is behind NAT/CGNAT and can SSH out to a VPS.\n1. On the VPS, set GatewayPorts clientspecified (or yes) in sshd_config and allow the public port.\n2. A: Cross-network access -> Reverse SSH: target user@vps, VPS port 41337, enable.\n3. A: set "Address peers should dial" to the VPS host or IP.\n4. Wait until the status shows running, then create a Direct invite.\n5. B joins the invite. A’s DSH stays behind NAT.\nTroubleshooting: read the ssh stderr in the status line, check the VPS firewall and GatewayPorts.',
      'tutorial.relay.title': 'Built-in relay (NAT to NAT)',
      'tutorial.relay.body': 'Use when both sides are behind NAT/CGNAT and a VPS is available.\n1. On the VPS: node relay.js --port 41338 --token a-long-random-secret (or dsh-peerweave-relay).\n2. Allow TCP 41338 on the VPS.\n3. A: Cross-network access -> Relay client: fill host, port and token.\n4. A: create an invite with mode Relay (NAT to NAT).\n5. B: join the code. Both sides dial out to the relay.\nThe relay only pairs a room and forwards ciphertext; it cannot read or impersonate. Reconnects reuse the room.',
      'tutorial.ipv6.title': 'IPv6 / dual-stack',
      'tutorial.ipv6.body': 'Use when both computers have working IPv6.\n1. A: Shared settings -> Listen address = IPv6 + IPv4 dual-stack (::).\n2. Allow the listen port for IPv6 in A’s firewall.\n3. A: set "Address peers should dial" to A’s IPv6 literal, without brackets.\n4. A: create a Direct invite; B joins.\n5. Verify IPv6 reachability first with ping6 or Test-NetConnection.',
      'tutorial.sshTunnel.title': 'SSH tunnel (B to A)',
      'tutorial.sshTunnel.body': 'Use when B can SSH to A and you do not want to expose the Peerweave port.\n1. A runs sshd and its DSH listens on 41337.\n2. B: when joining the invite, tick "Use an SSH tunnel", enter user@A and A’s listen port.\n3. The plugin runs ssh -L 127.0.0.1:<local>:127.0.0.1:41337 user@A.\n4. The SSH target must be the machine running DSH (forwarding goes to the SSH host’s loopback).\n5. For passphrase-protected keys, load them into ssh-agent first.',
      'tutorial.tailscale.title': 'Tailscale overlay',
      'tutorial.tailscale.body': 'Easiest option when the machines are far apart or behind CGNAT.\n1. Install Tailscale on both computers and sign in to the same account (same tailnet).\n2. Confirm both devices are online and note A’s 100.x.y.z address or MagicDNS name.\n3. A: set "Address peers should dial" to that address; create a Direct invite.\n4. B: join the invite. No port forwarding is needed.\n5. If a direct path is blocked it falls back to Tailscale DERP relays; Peerweave still encrypts end to end.\n6. Use Tailscale ACLs/tags to limit which devices may reach A.',
      'tutorial.zerotier.title': 'ZeroTier overlay',
      'tutorial.zerotier.body': 'Easiest option when the machines are far apart or behind CGNAT.\n1. Create a ZeroTier network and join both computers; authorize both members.\n2. Note A’s Managed IP.\n3. A: set "Address peers should dial" to that Managed IP; create a Direct invite.\n4. B: join the invite. No port forwarding is needed.\n5. Keep the network private; the Managed IP is only reachable by authorized members.',
      'net.title': 'Cross-network access',
      'net.intro': 'Reach peers outside the LAN with a custom dial address, reverse SSH, a relay, or a VPN overlay. The link stays end-to-end encrypted in every mode.',
      'net.bindHost': 'Listen address',
      'net.bindV4': 'IPv4 only (0.0.0.0)',
      'net.bindV6': 'IPv6 + IPv4 dual-stack (::)',
      'net.bindHint': 'Dual-stack lets IPv6 peers connect; the invite address still comes from “Address peers should dial”.',
      'net.allWorkspaces': 'History is grouped by every workspace registered on the peer; files let you pick a workspace root. No single shared-root selection is required.',
      'net.reverse': 'Reverse SSH (this machine behind NAT)',
      'net.reverseEnable': 'Run an outbound ssh -R tunnel to a VPS',
      'net.reverseTarget': 'SSH target (user@vps)',
      'net.reverseBindPort': 'Public port on the VPS',
      'net.reverseExtra': 'Extra ssh arguments (optional)',
      'net.reverseHint': 'The VPS sshd needs GatewayPorts clientspecified (or yes) so the forwarded port is reachable. Set “Address peers should dial” to the VPS host; direct invites then advertise the VPS port.',
      'net.relayClient': 'Relay client (for relay invites)',
      'net.relayHost': 'Relay host',
      'net.relayPort': 'Relay port',
      'net.relayToken': 'Relay token (optional)',
      'net.relayClientHint': 'Both sides connect outbound to this relay; no port forwarding is needed. Create the invite with mode “Relay”.',
      'net.relayServer': 'Relay server (run here)',
      'net.relayServerEnable': 'Run the relay listener on this machine',
      'net.relayServerHint': 'Usually this belongs on a public VPS; you can also run the stand-alone relay.js there instead.',
      'net.running': 'running',
      'net.stopped': 'stopped',
      'net.save': 'Save cross-network settings',
      'net.saved': 'Cross-network settings saved.',
      'net.guide': 'Overlay network guide (Tailscale / ZeroTier)',
      'net.guideHint': 'Easiest option when both machines are far apart or behind CGNAT: no port forwarding, no relay to operate.',
      'net.tailscaleGuide': 'Tailscale\n1. Install Tailscale on both computers and sign in to the same account (same tailnet).\n2. Confirm both devices are online and note A’s 100.x.y.z address or MagicDNS name.\n3. On A: Settings → Peerweave → “Address peers should dial” = that address; create a direct invite.\n4. On B: join the invite. No port forwarding is needed.\n5. If a direct path is blocked it falls back to Tailscale DERP relays; Peerweave still encrypts end to end.\n6. Use Tailscale ACLs/tags to limit which devices may reach A.',
      'net.zerotierGuide': 'ZeroTier\n1. Create a ZeroTier network and join both computers; authorize both members.\n2. Note A’s Managed IP.\n3. On A: “Address peers should dial” = that Managed IP; create a direct invite.\n4. On B: join the invite. No port forwarding is needed.\n5. Keep the network private; the Managed IP is only reachable by authorized members.',
      'invite.mode': 'Invite mode',
      'invite.modeDirect': 'Direct / reverse SSH',
      'invite.modeRelay': 'Relay (NAT to NAT)',
      'invite.modeRelayHint': 'Set the relay client above first. Both sides dial the relay; no reachable port is required on either peer.',
      'invite.dialHost': 'Custom dial host (optional)',
      'invite.dialPort': 'Custom dial port (optional)',
      'invite.dialHint': 'Overrides the address inside the invite. Useful for ngrok, frp, reverse SSH, or a port-forward that uses a different port.',
      'peers.relay': 'Relay',
      'peers.relayRole': 'role',
      'files.tooLarge': 'The file exceeds the sharing limit set by the peer.',
      'files.tooLargePreview': 'The file is too large for an inline preview. Copy it to your workspace instead.',
      'settings.listenPort': 'Listen port',
      'settings.sharedRoot': 'Shared workspace root',
      'settings.sharedRootHint': 'Leave empty to share this profile’s default workspace.',
      'settings.autoConnect': 'Reconnect known peers automatically',
      'settings.displayName': 'Display name',
      'settings.advertiseHost': 'Address peers should dial',
      'settings.advertiseHostHint': 'Leave empty to advertise the detected LAN address.',
      'settings.saved': 'Settings saved.',
      'password.title': 'Change password',
      'password.current': 'Current password',
      'password.next': 'New password',
      'password.change': 'Change password',
      'password.changed': 'Password changed.',
      'reset.title': 'Erase everything',
      'reset.warning': 'This deletes the identity key, the password, every trusted peer and all audit entries. It cannot be undone.',
      'reset.submit': 'Erase and start over',
      'reset.done': 'Peerweave was erased. Create a new password to start again.',
      'audit.title': 'Recent permission events',
      'audit.empty': 'Nothing recorded yet.',
      'history.title': 'Workspace history',
      'history.empty': 'No sessions in the shared workspace.',
      'history.load': 'Load history',
      'history.back': 'Back to sessions',
      'history.messages': 'messages',
      'files.title': 'Shared files',
      'files.workspaces': 'Workspaces',
      'files.empty': 'This folder is empty.',
      'files.root': 'Root',
      'files.up': 'Up',
      'files.copyLocal': 'Copy to my workspace',
      'files.copied': 'Copied to {0}',
      'files.binary': 'Binary file ({0} bytes)',
      'files.limit': 'Size limit',
      'chat.title': 'Chat with their DSH',
      'chat.placeholder': 'Message the remote DSH…',
      'chat.send': 'Send',
      'chat.needTier': 'This peer has not granted tier 3 (chat).',
      'chat.busy': 'The remote DSH is thinking…',
      'chat.empty': 'No messages yet.',
      'error.token': 'Enter the password to unlock this page.',
      'error.offline': 'The peer is offline. Connect it first.',
      'error.network': 'Could not reach the local Peerweave service.',
    }

    const ZH = {
      'section.title': 'Peerweave 加密互联',
      'section.description': '与其他电脑上的 DSH 建立加密链接。',
      'dock.title': 'Peerweave',
      'dock.setupChip': '设置 Peerweave',
      'status.connected': '已连接',
      'status.offline': '离线',
      'status.locked': '已锁定',
      'status.inbound': '对方接入',
      'status.outbound': '本机接入',
      'tier.0': '仅建立链接',
      'tier.1': '查看工作区',
      'tier.2': '读取文件',
      'tier.3': '与 DSH 对话',
      'tier.unknown': '未知',
      'tier.short.0': '链接',
      'tier.short.1': '查看',
      'tier.short.2': '文件',
      'tier.short.3': '对话',
      'common.password': '密码',
      'common.confirm': '确认',
      'common.cancel': '取消',
      'common.save': '保存',
      'common.copy': '复制',
      'common.copied': '已复制',
      'common.close': '关闭',
      'common.loading': '加载中…',
      'common.none': '无',
      'common.bytes': '字节',
      'common.time': '时间',
      'common.refresh': '刷新',
      'setup.title': '创建 Peerweave 密码',
      'setup.intro': 'Peerweave 会加密链路，并用密码加密本机身份密钥。请现在设置密码；以后每次修改权限都要再次验证它。',
      'setup.password': '新密码（至少 8 位）',
      'setup.confirm': '再次输入密码',
      'setup.displayName': '显示名称（可选）',
      'setup.submit': '创建密码库',
      'setup.tooShort': '请至少使用 8 个字符。',
      'setup.mismatch': '两次输入的密码不一致。',
      'setup.done': '密码库已创建。请妥善保管密码：忘记后只能重新配对全部节点。',
      'unlock.title': '解锁 Peerweave',
      'unlock.intro': '输入安装时设置的密码以解密身份密钥并启用节点连接。',
      'unlock.submit': '解锁',
      'recover.title': '忘记密码？',
      'recover.intro': '强制清除会把 Peerweave 恢复到刚安装、尚未设置密码的状态，并删除身份密钥、密码、全部节点和所有设置。',
      'recover.action': '强制清除 Peerweave…',
      'recover.start': '开始 10 秒确认',
      'recover.wait': '{0} 秒后可确认',
      'recover.confirm': '确认全部清除',
      'recover.cancel': '取消',
      'recover.warning': '此操作不可撤销。仅在确实忘记密码时使用。',
      'recover.done': 'Peerweave 已清除，请重新创建密码。',
      'peers.title': '已连接的 DSH',
      'peers.empty': '还没有节点。先在这里创建邀请码，再到另一台电脑上加入。',
      'peers.fingerprint': '指纹',
      'peers.grantedByMe': '允许对方在此电脑上',
      'peers.grantedToMe': '对方允许我',
      'peers.connect': '连接',
      'peers.disconnect': '断开',
      'peers.remove': '移除节点',
      'peers.removeConfirm': '移除这个节点？这会删除本机上的信任记录。',
      'peers.lastSeen': '最近活动',
      'peers.guest': '访客会话',
      'peers.transport': '连接方式',
      'grant.title': '我授予对方的权限',
      'grant.review': '检查更改',
      'grant.confirm': '确认更改',
      'grant.wait': '{0} 秒后可确认',
      'grant.applied': '权限已更新。',
      'grant.needsPassword': '修改权限需要输入密码。',
      'grant.warning':
        '第三档会让远端节点控制本机上的一个 DSH 智能体：它可以读取文件、执行命令并使用本工作区允许的所有工具。请只授予完全信任的人，并且必须等满 10 秒后再确认。',
      'invite.title': '邀请',
      'invite.intro': '邀请码包含本机地址、指纹和一次性配对密钥。请通过你信任的渠道发送。',
      'invite.create': '生成邀请码',
      'invite.created': '邀请码已生成，10 分钟内有效，只能使用一次。',
      'invite.join': '加入另一台 DSH',
      'invite.code': '邀请码',
      'invite.joinSubmit': '使用邀请码加入',
      'invite.ssh': '通过 SSH 隧道',
      'invite.sshTarget': 'SSH 目标（user@host）',
      'invite.sshPort': 'SSH 主机上对方的监听端口',
      'settings.title': '共享设置',
      'settings.maxFile': '允许对方读取的单文件上限（MiB）',
      'settings.maxFileHint': '适用于所有获得第二档及以上权限的节点。硬上限 2048 MiB（2 GiB）。',
      'tutorial.lan.title': '局域网直连',
      'tutorial.lan.body': '适用于两台电脑在同一 Wi-Fi / 交换机下。\n1. 两端都安装 Peerweave，设置密码并解锁。\n2. A：监听地址保持 IPv4（0.0.0.0），端口默认 41337。\n3. A：“供对方连接的地址”留空，自动使用检测到的局域网 IPv4。\n4. A：生成“直连”邀请码，发给 B。\n5. B：粘贴邀请码加入；若失败，在 A 的防火墙放行 TCP 41337。\n6. 配对后分别设置要授予对方的权限档位。',
      'tutorial.portForward.title': '公网 IPv4 + 端口映射',
      'tutorial.portForward.body': '适用于 A 有公网 IPv4 或 DDNS 域名。\n1. 路由器把 TCP 41337 转发到 A 的内网 IP:41337，并在系统防火墙放行。\n2. A：“供对方连接的地址”填公网 IP 或 DDNS 域名。\n3. A：生成“直连”邀请码；B 可从任意网络加入。\n4. 用手机热点或其他网络验证。\n如果路由器 WAN 地址与公网 IP 不一致（CGNAT），端口映射无效；请改用 Tailscale、中继或反向 SSH。',
      'tutorial.customDial.title': '自定义拨号地址/端口',
      'tutorial.customDial.body': '适用于邀请码地址不可达，或对外端口与监听端口不同。\n1. 先准备好通道：ngrok tcp 41337、frp、反向 SSH 或端口映射。\n2. A：正常生成“直连”邀请码。\n3. B：加入时在“自定义拨号地址/端口”填真实入口，例如 abc.tcp.ngrok.io 和 12345。\n4. 留空则使用邀请码内地址。\n只改拨号目标，邀请码指纹仍会校验 A 的身份；自定义地址会保存用于重连。',
      'tutorial.reverseSsh.title': '反向 SSH（A 在 NAT 后）',
      'tutorial.reverseSsh.body': '适用于 A 在 NAT/CGNAT 后，但能主动 SSH 到 VPS。\n1. VPS 的 sshd_config 设 GatewayPorts clientspecified（或 yes），并放行对外端口。\n2. A：跨公网连接 → 反向 SSH：填 user@vps、VPS 端口 41337，启用。\n3. A：“供对方连接的地址”填 VPS 域名或 IP。\n4. 状态显示 running 后，A 生成“直连”邀请码。\n5. B 加入邀请码；A 的 DSH 始终在 NAT 后。\n排查：看状态里的 ssh stderr、VPS 防火墙和 GatewayPorts。',
      'tutorial.relay.title': '内置中继（NAT 到 NAT）',
      'tutorial.relay.body': '适用于两端都在 NAT/CGNAT 后，且有一台 VPS。\n1. VPS：node relay.js --port 41338 --token 长随机串（或 dsh-peerweave-relay）。\n2. 在 VPS 防火墙放行 TCP 41338。\n3. A：跨公网连接 → 中继客户端：填地址、端口、token。\n4. A：创建邀请码时选“中继（NAT 到 NAT）”。\n5. B：粘贴邀请码加入；两端都主动连中继。\n中继只做房间配对和密文转发，无法读取或冒充；断线重连复用同一房间。',
      'tutorial.ipv6.title': 'IPv6 / 双栈',
      'tutorial.ipv6.body': '适用于两端都有可用 IPv6。\n1. A：共享设置 → 监听地址选 IPv6 + IPv4 双栈（::）。\n2. 在 A 的防火墙放行监听端口的 IPv6。\n3. A：“供对方连接的地址”填 A 的 IPv6 字面量（不要加方括号）。\n4. A 生成“直连”邀请码，B 加入。\n5. 先用 ping6 或 Test-NetConnection 验证 IPv6 可达性。',
      'tutorial.sshTunnel.title': 'SSH 隧道（B 到 A）',
      'tutorial.sshTunnel.body': '适用于 B 能 SSH 到 A，但不想暴露 Peerweave 端口。\n1. A 运行 sshd，且 DSH 监听 41337。\n2. B：加入邀请码时勾选“通过 SSH 隧道”，填 user@A 和 A 的监听端口。\n3. 插件执行 ssh -L 127.0.0.1:<本地端口>:127.0.0.1:41337 user@A。\n4. SSH 目标必须是运行 DSH 的机器（转发到 SSH 主机的 loopback）。\n5. 带口令的私钥请先加载到 ssh-agent。',
      'tutorial.tailscale.title': 'Tailscale 组网',
      'tutorial.tailscale.body': '两台机器离得远或在 CGNAT 后时最省事。\n1. 两台电脑都安装 Tailscale，登录同一账号（同一 tailnet）。\n2. 确认两台设备在线，记下 A 的 100.x.y.z 地址或 MagicDNS 名称。\n3. A：“供对方连接的地址”填该地址；生成“直连”邀请码。\n4. B：加入邀请码，不需要端口映射。\n5. 直连不通会自动走 DERP 中继；Peerweave 仍端到端加密。\n6. 用 Tailscale ACL/tag 限制哪些设备能访问 A。',
      'tutorial.zerotier.title': 'ZeroTier 组网',
      'tutorial.zerotier.body': '两台机器离得远或在 CGNAT 后时最省事。\n1. 创建 ZeroTier Network，两台电脑加入并授权。\n2. 记下 A 的 Managed IP。\n3. A：“供对方连接的地址”填该 Managed IP；生成“直连”邀请码。\n4. B：加入邀请码，不需要端口映射。\n5. 保持网络私有；Managed IP 只有被授权成员能访问。',
      'net.title': '跨公网连接',
      'net.intro': '通过自定义拨号地址、反向 SSH、中继或 VPN 组网连接局域网之外的节点；所有模式都保持端到端加密。',
      'net.bindHost': '监听地址',
      'net.bindV4': '仅 IPv4（0.0.0.0）',
      'net.bindV6': 'IPv6 + IPv4 双栈（::）',
      'net.bindHint': '双栈允许 IPv6 节点直连；邀请码里的地址仍来自“供对方连接的地址”。',
      'net.allWorkspaces': '历史记录按对方注册的全部工作区分组；文件可先选择工作区根目录。不需要在设置里只选一个共享工作区。',
      'net.reverse': '反向 SSH（本机在 NAT 后）',
      'net.reverseEnable': '主动向 VPS 建立 ssh -R 隧道',
      'net.reverseTarget': 'SSH 目标（user@vps）',
      'net.reverseBindPort': 'VPS 上对外暴露的端口',
      'net.reverseExtra': '额外 ssh 参数（可选）',
      'net.reverseHint': 'VPS 的 sshd 需要 GatewayPorts clientspecified（或 yes），否则转发端口只在 VPS 回环可访问。把“供对方连接的地址”设为 VPS 地址；直连邀请码会自动使用 VPS 端口。',
      'net.relayClient': '中继客户端（生成中继邀请码）',
      'net.relayHost': '中继服务器地址',
      'net.relayPort': '中继端口',
      'net.relayToken': '中继 token（可选）',
      'net.relayClientHint': '两端都主动连这个中继，双方都不需要端口映射。创建邀请码时选择“中继”。',
      'net.relayServer': '中继服务（在本机运行）',
      'net.relayServerEnable': '在本机启动中继监听',
      'net.relayServerHint': '通常应部署在公网 VPS；也可以直接在 VPS 上运行独立的 relay.js。',
      'net.running': '运行中',
      'net.stopped': '未运行',
      'net.save': '保存跨网设置',
      'net.saved': '跨网设置已保存。',
      'net.guide': '组网教程（Tailscale / ZeroTier）',
      'net.guideHint': '两台机器离得很远或在 CGNAT 后时最省事：不需要端口映射，也不需要自己维护中继。',
      'net.tailscaleGuide': 'Tailscale\n1. 两台电脑都安装 Tailscale，并登录同一账号（同一 tailnet）。\n2. 在管理台确认两台设备在线，记下 A 的 100.x.y.z 地址或 MagicDNS 名称。\n3. 在 A：设置 → Peerweave → “供对方连接的地址”填该地址；创建“直连”邀请码。\n4. 在 B：加入邀请码。不需要任何端口映射。\n5. 直连不通时会自动走 Tailscale DERP 中继；Peerweave 仍然端到端加密。\n6. 建议用 Tailscale ACL/tag 限制哪些设备可以访问 A。',
      'net.zerotierGuide': 'ZeroTier\n1. 创建 ZeroTier Network，两台电脑加入并授权。\n2. 记下 A 的 Managed IP。\n3. 在 A：“供对方连接的地址”填该 Managed IP；创建“直连”邀请码。\n4. 在 B：加入邀请码。不需要端口映射。\n5. 保持网络私有；Managed IP 只有被授权的成员能访问。',
      'invite.mode': '邀请方式',
      'invite.modeDirect': '直连 / 反向 SSH',
      'invite.modeRelay': '中继（NAT 到 NAT）',
      'invite.modeRelayHint': '请先配置上方的中继客户端。双方都主动连中继，不需要任何一端有可达端口。',
      'invite.dialHost': '自定义拨号地址（可选）',
      'invite.dialPort': '自定义拨号端口（可选）',
      'invite.dialHint': '覆盖邀请码内的地址，适用于 ngrok、frp、反向 SSH 或端口映射后端口不一致的情况。',
      'peers.relay': '中继',
      'peers.relayRole': '角色',
      'files.tooLarge': '文件超过对方设置的共享大小上限。',
      'files.tooLargePreview': '文件太大，无法内联预览。请使用「复制到我的工作区」传输。',
      'settings.listenPort': '监听端口',
      'settings.sharedRoot': '共享工作区根目录',
      'settings.sharedRootHint': '留空则共享当前配置档的默认工作区。',
      'settings.autoConnect': '自动重连已知节点',
      'settings.displayName': '显示名称',
      'settings.advertiseHost': '供对方连接的地址',
      'settings.advertiseHostHint': '留空则使用自动检测到的局域网地址。',
      'settings.saved': '设置已保存。',
      'password.title': '修改密码',
      'password.current': '当前密码',
      'password.next': '新密码',
      'password.change': '修改密码',
      'password.changed': '密码已修改。',
      'reset.title': '清空一切',
      'reset.warning': '这会删除身份密钥、密码、全部受信节点和审计记录，且无法撤销。',
      'reset.submit': '清空并重新开始',
      'reset.done': 'Peerweave 已清空。请重新创建密码。',
      'audit.title': '最近的权限事件',
      'audit.empty': '暂无记录。',
      'history.title': '工作区历史',
      'history.empty': '共享工作区里没有会话。',
      'history.load': '加载历史',
      'history.back': '返回会话列表',
      'history.messages': '条消息',
      'files.title': '共享文件',
      'files.workspaces': '工作区',
      'files.empty': '这个文件夹是空的。',
      'files.root': '根目录',
      'files.up': '上一级',
      'files.copyLocal': '复制到我的工作区',
      'files.copied': '已复制到 {0}',
      'files.binary': '二进制文件（{0} 字节）',
      'files.limit': '大小限制',
      'chat.title': '与对方 DSH 对话',
      'chat.placeholder': '给远端 DSH 发消息…',
      'chat.send': '发送',
      'chat.needTier': '对方没有授予第三档（对话）权限。',
      'chat.busy': '远端 DSH 正在思考…',
      'chat.empty': '还没有消息。',
      'error.token': '请输入密码解锁此页面。',
      'error.offline': '节点离线，请先连接。',
      'error.network': '无法连接本机 Peerweave 服务。',
    }

    // ------------------------------------------------------------------
    // In-memory page session (the unlock token never touches storage)
    // ------------------------------------------------------------------
    const session = { token: null, expiresAt: 0, listeners: new Set() }

    const peerPanel = { open: false, peerId: null, listeners: new Set() }

    function setPeerPanel(next) {
      Object.assign(peerPanel, next)
      for (const listener of [...peerPanel.listeners]) listener()
    }

    function usePeerPanel() {
      const [, setRevision] = useState(0)
      useEffect(() => {
        const bump = () => setRevision((value) => value + 1)
        peerPanel.listeners.add(bump)
        return () => peerPanel.listeners.delete(bump)
      }, [])
      return peerPanel
    }

    function setSession(token, expiresAt) {
      session.token = token || null
      session.expiresAt = expiresAt || 0
      for (const listener of [...session.listeners]) listener()
    }

    function useSession() {
      const [, setRevision] = useState(0)
      useEffect(() => {
        const bump = () => setRevision((value) => value + 1)
        session.listeners.add(bump)
        return () => session.listeners.delete(bump)
      }, [])
      return session
    }

    class UiError extends Error {
      constructor(code, message) {
        super(message || code)
        this.code = code || 'error'
      }
    }

    async function request(action, body, method) {
      const headers = { 'x-peerweave': '1' }
      if (method !== 'GET') headers['content-type'] = 'application/json'
      if (session.token) headers['x-peerweave-token'] = session.token
      let response
      try {
        response = await fetch(`${API}/${action}`, {
          method: method || 'POST',
          headers,
          body: method === 'GET' ? undefined : JSON.stringify(body || {}),
          credentials: 'same-origin',
          cache: 'no-store',
        })
      } catch {
        throw new UiError('network', 'network')
      }
      let payload = null
      try {
        payload = await response.json()
      } catch {
        payload = null
      }
      if (!payload) throw new UiError('bad-response', `HTTP ${response.status}`)
      if (!payload.ok) {
        const code = payload.error && payload.error.code ? payload.error.code : 'error'
        if (code === 'token-required') setSession(null, 0)
        throw new UiError(code, (payload.error && payload.error.message) || code)
      }
      return payload.data === undefined ? payload : payload.data
    }

    const post = (action, body) => request(action, body, 'POST')
    const getPublic = () => request('public', null, 'GET')

    // ------------------------------------------------------------------
    // Hooks and small primitives
    // ------------------------------------------------------------------
    function useT(ctx) {
      const [, setRevision] = useState(0)
      useEffect(() => {
        return ctx.locale.subscribe(() => setRevision((value) => value + 1))
      }, [ctx])
      return useCallback((key, ...args) => {
        const text = ctx.locale.bind(NS)(key)
        if (!args.length) return text
        return args.reduce((acc, value, index) => acc.replace(`{${index}}`, String(value)), text)
      }, [ctx])
    }

    function usePublic(active, intervalMs) {
      const [state, setState] = useState(null)
      const [error, setError] = useState('')
      const load = useCallback(async () => {
        try {
          const next = await getPublic()
          setState(next)
          setError('')
        } catch (failure) {
          setError(failure.message === 'network' ? 'network' : failure.message)
        }
      }, [])
      useEffect(() => {
        if (!active) return undefined
        let alive = true
        const tick = () => {
          if (!alive) return
          load()
        }
        tick()
        const timer = setInterval(tick, intervalMs || 4000)
        return () => {
          alive = false
          clearInterval(timer)
        }
      }, [active, intervalMs, load])
      return { state, error, reload: load }
    }

    const CSS = [
      '.pwv-root{font-size:13px;line-height:1.45;color:var(--dsw-alias-label-primary)}',
      '.pwv-dock{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:4px 2px;color:var(--dsw-alias-label-secondary);font-size:12px}',
      '.pwv-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-1);border-radius:999px;padding:3px 9px;cursor:pointer;font:inherit;color:inherit}',
      '.pwv-chip:hover{background:var(--dsw-alias-interactive-bg-hover)}',
      '.pwv-chip.on{border-color:var(--dsw-alias-brand-primary)}',
      '.pwv-dot{width:7px;height:7px;border-radius:50%;flex:0 0 auto}',
      '.pwv-dot.on{background:var(--dsw-alias-state-success-primary)}',
      '.pwv-dot.off{background:var(--dsw-alias-state-idle-primary)}',
      '.pwv-dot.warn{background:var(--dsw-alias-state-warn-primary)}',
      '.pwv-panel{margin-top:6px;border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);max-height:380px;display:flex;flex-direction:column;overflow:hidden;flex:1 1 100%}',
      '.pwv-panelbody{overflow:auto;padding:10px}',
      '.pwv-card{border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);padding:12px;margin:10px 0}',
      '.pwv-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}',
      '.pwv-col{display:flex;flex-direction:column;gap:6px}',
      '.pwv-grow{flex:1 1 auto;min-width:0}',
      '.pwv-input{font:inherit;font-size:12px;padding:5px 8px;border-radius:6px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);min-width:0;outline:none}',
      '.pwv-input:focus{border-color:var(--dsw-alias-brand-primary)}',
      '.pwv-btn{font:inherit;font-size:12px;padding:5px 10px;border-radius:6px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);cursor:pointer}',
      '.pwv-btn:hover{background:var(--dsw-alias-interactive-bg-hover)}',
      '.pwv-btn:disabled{opacity:.5;cursor:default}',
      '.pwv-btn.primary{background:var(--dsw-alias-brand-primary);border-color:transparent;color:var(--dsw-alias-label-primary-inverted)}',
      '.pwv-btn.danger{color:var(--dsw-alias-state-error-primary)}',
      '.pwv-btn.ghost{border-color:transparent;background:transparent}',
      '.pwv-muted{color:var(--dsw-alias-label-tertiary);font-size:12px}',
      '.pwv-err{color:var(--dsw-alias-state-error-primary);font-size:12px;white-space:pre-wrap;word-break:break-word}',
      '.pwv-ok{color:var(--dsw-alias-state-success-primary);font-size:12px}',
      '.pwv-warn{background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-state-warn-primary);border-radius:8px;padding:9px;color:var(--dsw-alias-state-warn-label);font-size:12px}',
      '.pwv-title{font-size:16px;font-weight:600;margin:0 0 2px}',
      '.pwv-h{font-size:13px;font-weight:600;margin:16px 0 4px}',
      '.pwv-sub{font-size:12px;color:var(--dsw-alias-label-tertiary);margin:0 0 8px}',
      '.pwv-list{display:flex;flex-direction:column;gap:1px}',
      '.pwv-item{display:flex;gap:8px;align-items:center;padding:5px 7px;border-radius:6px;cursor:pointer;border:0;background:transparent;text-align:left;color:inherit;font:inherit;width:100%}',
      '.pwv-item:hover{background:var(--dsw-alias-interactive-bg-hover)}',
      '.pwv-item.active{background:var(--dsw-alias-interactive-bg-hover)}',
      '.pwv-pre{white-space:pre-wrap;word-break:break-word;background:var(--dsw-alias-bg-layer-2);border-radius:8px;padding:9px;max-height:260px;overflow:auto;font-family:ui-monospace,Consolas,monospace;font-size:12px;margin:0}',
      '.pwv-tabs{display:flex;gap:2px;border-bottom:1px solid var(--dsw-alias-border-l1);padding:0 8px}',
      '.pwv-tab{font:inherit;font-size:12px;background:transparent;border:0;border-bottom:2px solid transparent;padding:7px 8px;cursor:pointer;color:var(--dsw-alias-label-secondary)}',
      '.pwv-tab.active{border-bottom-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary)}',
      '.pwv-badge{font-size:10.5px;border:1px solid var(--dsw-alias-border-l1);border-radius:999px;padding:1px 6px;color:var(--dsw-alias-label-secondary);white-space:nowrap}',
      '.pwv-danger-badge{font-size:10.5px;border:1px solid var(--dsw-alias-state-warn-primary);color:var(--dsw-alias-state-warn-label);border-radius:999px;padding:1px 6px;white-space:nowrap}',
      '.pwv-code{font-family:ui-monospace,Consolas,monospace;font-size:11px;word-break:break-all;background:var(--dsw-alias-bg-layer-2);padding:8px;border-radius:8px;max-height:96px;overflow:auto}',
      '.pwv-mono{font-family:ui-monospace,Consolas,monospace;font-size:11px}',
      '.pwv-sep{height:1px;background:var(--dsw-alias-border-l1);margin:10px 0}',
      '.pwv-flex1{flex:1 1 auto}',
      '.pwv-nowrap{white-space:nowrap}',
      '.pwv-field{display:flex;flex-direction:column;gap:3px;margin:6px 0}',
      '.pwv-label{font-size:12px;color:var(--dsw-alias-label-secondary)}',
      '.pwv-chat{display:flex;flex-direction:column;gap:6px;max-height:220px;overflow:auto;margin-bottom:8px}',
      '.pwv-msg{border-radius:8px;padding:7px 9px;font-size:12px;white-space:pre-wrap;word-break:break-word;max-width:88%}',
      '.pwv-msg.user{align-self:flex-end;background:var(--dsw-alias-bg-layer-2)}',
      '.pwv-msg.assistant{align-self:flex-start;border:1px solid var(--dsw-alias-border-l1)}',
      '.pwv-msg.error{align-self:stretch;color:var(--dsw-alias-state-error-primary);border:1px solid var(--dsw-alias-state-error-primary)}',
      '.pwv-guide{margin-top:12px;border-top:1px solid var(--dsw-alias-border-l1);padding-top:8px}',
      '.pwv-guide summary{cursor:pointer;font-size:12px;color:var(--dsw-alias-label-secondary)}',
      '.pwv-tutorial{margin-top:6px;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;padding:0 8px}',
      '.pwv-tutorial summary{cursor:pointer;font-size:12px;color:var(--dsw-alias-label-secondary);padding:7px 0}',
      '.pwv-guide-body{white-space:pre-line;font-size:12px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2);border-radius:8px;padding:8px;margin:0 0 8px;line-height:1.5}',
      '.pwv-sideentry{display:flex;align-items:center;min-height:36px}',
      '.pwv-sidebtn{display:flex;align-items:center;gap:8px;width:100%;height:36px;padding:0 8px;border:0;border-radius:8px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:14px;line-height:20px;cursor:pointer;text-align:start}',
      '.pwv-sidebtn:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}',
      '.pwv-sidebtn:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}',
      '.pwv-overlay{position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,.38);display:flex;align-items:center;justify-content:center;padding:24px}',
      '.pwv-modal{display:flex;flex-direction:column;width:min(1120px,96vw);height:min(780px,90vh);background:var(--dsw-alias-bg-base);border:1px solid var(--dsw-alias-border-l1);border-radius:14px;box-shadow:0 24px 64px rgba(0,0,0,.28);overflow:hidden}',
      '.pwv-modalhead{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--dsw-alias-border-l1)}',
      '.pwv-modalbody{display:flex;flex:1;min-height:0}',
      '.pwv-peerlist{width:230px;flex:0 0 230px;border-right:1px solid var(--dsw-alias-border-l1);overflow:auto;padding:8px}',
      '.pwv-modalcontent{flex:1;min-width:0;overflow:auto;padding:12px}',
      '.pwv-modaltabs{display:flex;gap:2px;padding:0 12px;border-bottom:1px solid var(--dsw-alias-border-l1)}',
    ].join('')

    function Styles() {
      return h('style', { dangerouslySetInnerHTML: { __html: CSS } })
    }

    function Btn({ children, primary, danger, ghost, ...rest }) {
      const className = ['pwv-btn', primary ? 'primary' : '', danger ? 'danger' : '', ghost ? 'ghost' : ''].filter(Boolean).join(' ')
      return h('button', { type: 'button', className, ...rest }, children)
    }

    function Input({ value, onChange, placeholder, type, disabled, autoFocus, onEnter }) {
      return h('input', {
        className: 'pwv-input',
        type: type || 'text',
        value: value == null ? '' : value,
        placeholder,
        disabled,
        autoFocus,
        onChange: (event) => onChange(event.target.value),
        onKeyDown: onEnter ? (event) => { if (event.key === 'Enter') onEnter() } : undefined,
      })
    }

    function Field({ label, hint, children }) {
      return h('label', { className: 'pwv-field' },
        h('span', { className: 'pwv-label' }, label),
        children,
        hint ? h('span', { className: 'pwv-muted' }, hint) : null)
    }

    function ErrorLine({ text }) {
      if (!text) return null
      return h('div', { className: 'pwv-err' }, text)
    }

    function OkLine({ text }) {
      if (!text) return null
      return h('div', { className: 'pwv-ok' }, text)
    }

    function formatBytes(value) {
      const bytes = Number(value) || 0
      if (bytes < 1024) return `${bytes} B`
      if (bytes < MI_B) return `${(bytes / 1024).toFixed(1)} KiB`
      return `${(bytes / MI_B).toFixed(1)} MiB`
    }

    function formatTime(value) {
      if (!value) return '—'
      try {
        return new Date(value).toLocaleString()
      } catch {
        return String(value)
      }
    }

    function errorLabel(t, failure) {
      if (!failure) return ''
      const code = failure.code || ''
      if (code === 'token-required') return t('error.token')
      if (code === 'not-connected' || code === 'offline') return t('error.offline')
      if (code === 'file-needs-transfer') return t('files.tooLargePreview')
      if (code === 'file-too-large') return t('files.tooLarge')
      if (failure.message === 'network') return t('error.network')
      return failure.message || code || String(failure)
    }

    function copyText(text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text)
          return true
        }
      } catch {
        /* ignore */
      }
      return false
    }

    // ------------------------------------------------------------------
    // Unlock form (shared by dock and settings)
    // ------------------------------------------------------------------
    function UnlockForm({ t, onDone, compact }) {
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      async function submit() {
        if (!password) return
        setBusy(true)
        setError('')
        try {
          const data = await post('unlock', { password })
          setSession(data.token, data.expiresAt)
          setPassword('')
          if (onDone) onDone()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }
      return h('div', { className: compact ? 'pwv-row' : 'pwv-col' },
        compact ? null : h('div', { className: 'pwv-sub' }, t('unlock.intro')),
        h('div', { className: 'pwv-row' },
          h(Input, {
            value: password,
            onChange: setPassword,
            type: 'password',
            placeholder: t('unlock.title'),
            disabled: busy,
            onEnter: submit,
          }),
          h(Btn, { primary: true, onClick: submit, disabled: busy || !password }, busy ? t('common.loading') : t('unlock.submit'))),
        h(ErrorLine, { text: error }))
    }

    // ------------------------------------------------------------------
    // Forgot-password escape hatch: 10-second server-enforced confirmation
    // ------------------------------------------------------------------
    function ForceResetCard({ t, onDone }) {
      const [step, setStep] = useState('idle')
      const [pending, setPending] = useState(null)
      const [tick, setTick] = useState(Date.now())
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [done, setDone] = useState('')

      useEffect(() => {
        if (!pending) return undefined
        const timer = setInterval(() => setTick(Date.now()), 250)
        return () => clearInterval(timer)
      }, [pending])

      const remaining = pending ? Math.max(0, Math.ceil((pending.earliestAt - tick) / 1000)) : 0

      function cancel() {
        setStep('idle')
        setPending(null)
        setError('')
      }

      async function start() {
        setBusy(true)
        setError('')
        setDone('')
        try {
          const data = await post('recover/prepare', {})
          setPending(data)
          setTick(Date.now())
          setStep('counting')
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      async function confirm() {
        if (!pending || remaining > 0) return
        setBusy(true)
        setError('')
        try {
          await post('recover/commit', { nonce: pending.nonce, confirm: 'ERASE' })
          setSession(null, 0)
          setPending(null)
          setStep('idle')
          setDone(t('recover.done'))
          if (onDone) onDone()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-sep' }),
        h('div', { className: 'pwv-h' }, t('recover.title')),
        h('div', { className: 'pwv-sub' }, t('recover.intro')),
        step === 'idle'
          ? h('div', { className: 'pwv-row' },
            h(Btn, { danger: true, onClick: () => { setStep('armed'); setError(''); setDone('') } }, t('recover.action')))
          : null,
        step === 'armed'
          ? h('div', { className: 'pwv-col' },
            h('div', { className: 'pwv-warn' }, t('recover.warning')),
            h('div', { className: 'pwv-row' },
              h(Btn, { danger: true, onClick: start, disabled: busy }, busy ? t('common.loading') : t('recover.start')),
              h(Btn, { ghost: true, onClick: cancel, disabled: busy }, t('recover.cancel'))))
          : null,
        step === 'counting'
          ? h('div', { className: 'pwv-col' },
            h('div', { className: 'pwv-warn' }, t('recover.warning')),
            h('div', { className: 'pwv-row' },
              h(Btn, { danger: true, onClick: confirm, disabled: busy || remaining > 0 },
                remaining > 0 ? t('recover.wait', remaining) : t('recover.confirm')),
              h(Btn, { ghost: true, onClick: cancel, disabled: busy }, t('recover.cancel'))))
          : null,
        h(ErrorLine, { text: error }),
        h(OkLine, { text: done }))
    }

    // ------------------------------------------------------------------
    // Sidebar entry + full peer workspace browser
    // ------------------------------------------------------------------
    function PeerSidebarEntry({ ctx, wide }) {
      const t = useT(ctx)
      const { state } = usePublic(true, 6000)
      const peers = state && Array.isArray(state.peers) ? state.peers : []
      const connected = peers.some((entry) => entry.connected)
      const label = peers.length === 1
        ? peers[0].name
        : peers.length > 1
          ? `${t('dock.title')} · ${peers.length}`
          : t('dock.title')
      return h('div', {
        className: 'pwv-sideentry',
        style: { display: 'flex', alignItems: 'center', minHeight: 36 },
      },
      h(Styles),
      h('button', {
        type: 'button',
        className: 'pwv-sidebtn',
        title: peers.length === 1 ? `${peers[0].name} — ${t('section.title')}` : t('section.title'),
        onClick: () => setPeerPanel({ open: true }),
        style: {
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          width: '100%',
          height: 36,
          padding: '0 8px',
          border: 0,
          borderRadius: 8,
          background: 'transparent',
          color: 'var(--dsw-alias-label-secondary)',
          font: 'inherit',
          fontSize: 14,
          lineHeight: '20px',
          textAlign: 'start',
          cursor: 'pointer',
        },
      },
      h('span', {
        style: {
          width: 8,
          height: 8,
          flex: '0 0 auto',
          borderRadius: '50%',
          background: state && state.locked
            ? 'var(--dsw-alias-state-warn-primary)'
            : connected
              ? 'var(--dsw-alias-state-success-primary)'
              : 'var(--dsw-alias-label-tertiary)',
        },
      }),
      wide === false
        ? h('span', { style: { fontSize: 16, lineHeight: 1 } }, '◈')
        : h('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, label)))
    }

    function PeerOverlay({ ctx }) {
      const t = useT(ctx)
      const panel = usePeerPanel()
      const current = useSession()
      const { state } = usePublic(panel.open, 4000)
      const [tab, setTab] = useState('history')

      if (!panel.open) return null
      const peers = state && Array.isArray(state.peers) ? state.peers : []
      const peer = peers.find((entry) => entry.id === panel.peerId) || peers[0] || null
      return h('div', {
        className: 'pwv-overlay',
        onMouseDown: (event) => {
          if (event.target === event.currentTarget) setPeerPanel({ open: false })
        },
      },
      h('div', { className: 'pwv-modal', role: 'dialog', 'aria-label': t('section.title') },
        h(Styles),
        h('div', { className: 'pwv-modalhead' },
          h('strong', { className: 'pwv-grow' }, t('section.title')),
          h('span', { className: 'pwv-muted' }, state && state.locked ? t('status.locked') : `${peers.length} ${t('peers.title')}`),
          h(Btn, { ghost: true, onClick: () => setPeerPanel({ open: false }), title: t('common.close') }, '×')),
        h('div', { className: 'pwv-modalbody' },
          h('div', { className: 'pwv-peerlist' },
            peers.length === 0 ? h('div', { className: 'pwv-muted' }, t('peers.empty')) : null,
            peers.map((entry) => h('button', {
              key: entry.id,
              type: 'button',
              className: `pwv-item${peer && peer.id === entry.id ? ' active' : ''}`,
              onClick: () => setPeerPanel({ peerId: entry.id }),
            },
            h('span', { className: `pwv-dot ${entry.connected ? 'on' : 'off'}` }),
            h('span', { className: 'pwv-grow', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, entry.name),
            h('span', { className: 'pwv-badge' }, t(`tier.short.${entry.remoteTier >= 0 ? entry.remoteTier : 0}`))))),
          h('div', { className: 'pwv-modalcontent' },
            !state ? h('div', { className: 'pwv-muted' }, t('common.loading'))
              : !state.passwordSet ? h(SetupCard, { t, onDone: () => {} })
                : !current.token || state.locked ? h(UnlockForm, { t, onDone: () => {} })
                  : !peer ? h('div', { className: 'pwv-muted' }, t('peers.empty'))
                  : h('div', null,
                    h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
                      h('strong', { className: 'pwv-grow' }, peer.name),
                      h('span', { className: 'pwv-muted pwv-mono' }, peer.endpoint || ''),
                      h('span', { className: 'pwv-badge' }, peer.connected ? t('status.connected') : t('status.offline'))),
                    h('div', { className: 'pwv-modaltabs' },
                      h('button', { type: 'button', className: `pwv-tab${tab === 'history' ? ' active' : ''}`, onClick: () => setTab('history') }, t('history.title')),
                      h('button', { type: 'button', className: `pwv-tab${tab === 'files' ? ' active' : ''}`, onClick: () => setTab('files') }, t('files.title')),
                      h('button', { type: 'button', className: `pwv-tab${tab === 'chat' ? ' active' : ''}`, onClick: () => setTab('chat') }, t('chat.title'))),
                    h('div', { style: { paddingTop: 8 } },
                      tab === 'history' ? h(HistoryTab, { t, peer, reload: () => {} }) : null,
                      tab === 'files' ? h(FilesTab, { t, peer }) : null,
                      tab === 'chat' ? h(ChatTab, { t, peer }) : null))))))
    }

    // ------------------------------------------------------------------
    // Dock: connected DSHs in the workspace
    // ------------------------------------------------------------------
    function Dock({ ctx }) {
      const t = useT(ctx)
      const current = useSession()
      const { state, error, reload } = usePublic(true, 4000)
      const [panel, setPanel] = useState(null)
      const [tab, setTab] = useState('history')

      if (error && !state) {
        return h('div', { className: 'pwv-root pwv-dock' }, h(Styles), h('span', { className: 'pwv-err' }, error === 'network' ? t('error.network') : error))
      }
      if (!state || !state.ok) return null
      const peers = Array.isArray(state.peers) ? state.peers : []
      const hasPeers = peers.length > 0
      const needsSetup = !state.passwordSet
      if (!needsSetup && !state.locked && !hasPeers) return null
      if (!needsSetup && !state.locked && !current.token && !hasPeers) return null

      const peer = hasPeers && panel && panel !== 'setup' && panel !== 'unlock'
        ? peers.find((entry) => entry.id === panel) || null
        : null
      const showSetup = needsSetup && panel === 'setup'
      const showUnlock = state.locked && panel === 'unlock'

      return h('div', { className: 'pwv-root' },
        h(Styles),
        h('div', { className: 'pwv-dock' },
          h('span', { className: 'pwv-muted' }, t('dock.title')),
          needsSetup
            ? h('button', {
              type: 'button',
              className: `pwv-chip${showSetup ? ' on' : ''}`,
              onClick: () => setPanel(showSetup ? null : 'setup'),
            },
            h('span', { className: 'pwv-dot warn' }),
            h('span', { className: 'pwv-nowrap' }, t('dock.setupChip')))
            : null,
          state.locked
            ? h('button', {
              type: 'button',
              className: `pwv-chip${showUnlock ? ' on' : ''}`,
              onClick: () => setPanel(showUnlock ? null : 'unlock'),
            },
            h('span', { className: 'pwv-dot warn' }),
            h('span', { className: 'pwv-nowrap' }, t('dock.title')),
            h('span', { className: 'pwv-badge' }, t('status.locked')))
            : null,
          peers.map((entry) => h('button', {
            key: entry.id,
            type: 'button',
            className: `pwv-chip${(panel === entry.id && !showSetup && !showUnlock) ? ' on' : ''}`,
            title: `${entry.fingerprint}${entry.connected ? '' : ' · ' + t('status.offline')}`,
            onClick: () => {
              setPanel(panel === entry.id ? null : entry.id)
              setTab('history')
            },
          },
          h('span', { className: `pwv-dot ${state.locked ? 'warn' : entry.connected ? 'on' : 'off'}` }),
          h('span', { className: 'pwv-nowrap' }, entry.name),
          h('span', { className: 'pwv-badge' }, t(`tier.short.${entry.remoteTier >= 0 ? entry.remoteTier : 0}`))))),
        showSetup
          ? h('div', { className: 'pwv-panel' },
            h('div', { className: 'pwv-panelbody' },
              h(SetupCard, {
                t,
                onDone: () => {
                  reload()
                  setPanel(null)
                },
              })))
          : null,
        showUnlock
          ? h('div', { className: 'pwv-panel' },
            h('div', { className: 'pwv-panelbody' },
              h(UnlockForm, { t, onDone: reload })))
          : null,
        peer
          ? h('div', { className: 'pwv-panel' },
            h('div', { className: 'pwv-row', style: { padding: '7px 10px', borderBottom: '1px solid var(--dsw-alias-border-l1)' } },
              h('span', { className: `pwv-dot ${peer.connected ? 'on' : 'off'}` }),
              h('strong', { className: 'pwv-grow' }, peer.name),
              h('span', { className: 'pwv-badge' }, `${t('peers.grantedToMe')}: ${peer.remoteTier >= 0 ? t(`tier.${peer.remoteTier}`) : t('tier.unknown')}`),
              h(Btn, { ghost: true, onClick: () => setPanel(null), title: t('common.close') }, '×')),
            h('div', { className: 'pwv-tabs' },
              h('button', { type: 'button', className: `pwv-tab${tab === 'history' ? ' active' : ''}`, onClick: () => setTab('history') }, t('history.title')),
              h('button', { type: 'button', className: `pwv-tab${tab === 'files' ? ' active' : ''}`, onClick: () => setTab('files') }, t('files.title')),
              h('button', { type: 'button', className: `pwv-tab${tab === 'chat' ? ' active' : ''}`, onClick: () => setTab('chat') }, t('chat.title'))),
            !current.token
              ? h('div', { className: 'pwv-panelbody' }, h(UnlockForm, { t, onDone: reload }))
              : h('div', { className: 'pwv-panelbody' },
                tab === 'history' ? h(HistoryTab, { t, peer, reload }) : null,
                tab === 'files' ? h(FilesTab, { t, peer }) : null,
                tab === 'chat' ? h(ChatTab, { t, peer }) : null))
          : null)
    }

    function HistoryTab({ t, peer, reload }) {
      const [list, setList] = useState(null)
      const [detail, setDetail] = useState(null)
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')

      const loadList = useCallback(async () => {
        setBusy(true)
        setError('')
        try {
          setList(await post('remote/history/list', { peerId: peer.id }))
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }, [peer.id, t])

      useEffect(() => {
        loadList()
      }, [loadList])

      async function openSession(sessionId) {
        setBusy(true)
        setError('')
        try {
          setDetail(await post('remote/history/read', { peerId: peer.id, sessionId }))
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      if (detail) {
        return h('div', null,
          h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
            h(Btn, { ghost: true, onClick: () => setDetail(null) }, `← ${t('history.back')}`),
            h('strong', { className: 'pwv-grow' }, detail.title || detail.sessionId),
            h('span', { className: 'pwv-badge' }, `${detail.messages.length} ${t('history.messages')}`)),
          h(ErrorLine, { text: error }),
          h('div', { className: 'pwv-col' },
            detail.messages.length === 0 ? h('span', { className: 'pwv-muted' }, t('history.empty')) : null,
            detail.messages.map((message, index) => h('div', { key: `${message.seq}-${index}`, className: 'pwv-msg ' + (message.role === 'assistant' ? 'assistant' : 'user') },
              h('div', { className: 'pwv-muted' }, `${message.role} · ${formatTime(message.time)}`),
              h('div', null, message.text)))))
      }

      const groups = list && Array.isArray(list.workspaces) && list.workspaces.length > 0
        ? list.workspaces
        : (list ? [{ id: 'all', title: '', path: '', sessions: list.sessions || [] }] : [])

      return h('div', null,
        h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
          h('strong', { className: 'pwv-grow' }, t('history.title')),
          h(Btn, { ghost: true, onClick: loadList, disabled: busy }, busy ? t('common.loading') : t('common.refresh'))),
        h(ErrorLine, { text: error }),
        !list ? (busy ? h('span', { className: 'pwv-muted' }, t('common.loading')) : null)
          : groups.length === 0 || groups.every((group) => group.sessions.length === 0)
            ? h('span', { className: 'pwv-muted' }, t('history.empty'))
            : h('div', { className: 'pwv-col', style: { gap: 8 } },
              groups.filter((group) => group.sessions.length > 0).map((group) => h('div', { key: group.id, className: 'pwv-col' },
                group.title
                  ? h('div', { className: 'pwv-row' },
                    h('span', { className: 'pwv-mono pwv-grow' }, group.title),
                    group.path ? h('span', { className: 'pwv-muted pwv-mono' }, group.path) : null)
                  : null,
                h('div', { className: 'pwv-list' },
                  group.sessions.map((entry) => h('button', { key: entry.id, type: 'button', className: 'pwv-item', onClick: () => openSession(entry.id) },
                    h('span', { className: `pwv-dot ${entry.running ? 'on' : 'off'}` }),
                    h('span', { className: 'pwv-grow', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, entry.title),
                    h('span', { className: 'pwv-muted pwv-nowrap' }, formatTime(entry.updatedAt)))))))))
    }

    function FilesTab({ t, peer }) {
      const [workspaces, setWorkspaces] = useState(null)
      const [workspace, setWorkspace] = useState(null)
      const [listing, setListing] = useState(null)
      const [file, setFile] = useState(null)
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [note, setNote] = useState('')

      const loadWorkspaces = useCallback(async () => {
        setBusy(true)
        setError('')
        setFile(null)
        setListing(null)
        try {
          const data = await post('remote/files/workspaces', { peerId: peer.id })
          const list = (data && data.workspaces) || []
          setWorkspaces(list)
          if (list.length === 1) setWorkspace(list[0])
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }, [peer.id, t])

      const load = useCallback(async (path, target) => {
        const current = target || workspace
        if (!current) return
        setBusy(true)
        setError('')
        setFile(null)
        try {
          setListing(await post('remote/files/list', { peerId: peer.id, path: path || '', workspaceId: current.id }))
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }, [peer.id, t, workspace])

      useEffect(() => {
        loadWorkspaces()
      }, [loadWorkspaces])

      useEffect(() => {
        if (workspace) load('', workspace)
      }, [workspace && workspace.id])

      async function openFile(path) {
        if (!workspace) return
        setBusy(true)
        setError('')
        setNote('')
        try {
          setFile(await post('remote/files/read', { peerId: peer.id, path, workspaceId: workspace.id }))
        } catch (failure) {
          if (failure.code === 'file-needs-transfer' || failure.code === 'file-too-large') {
            setFile({
              path,
              encoding: 'unavailable',
              bytes: null,
              note: t(failure.code === 'file-needs-transfer' ? 'files.tooLargePreview' : 'files.tooLarge'),
            })
          } else {
            setError(errorLabel(t, failure))
          }
        } finally {
          setBusy(false)
        }
      }

      async function copyLocal(path) {
        if (!workspace) return
        setBusy(true)
        setError('')
        setNote('')
        try {
          const result = await post('remote/copy', { peerId: peer.id, path, workspaceId: workspace.id })
          setNote(t('files.copied', result.localPath))
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      function backToWorkspaces() {
        setWorkspace(null)
        setListing(null)
        setFile(null)
        setError('')
        setNote('')
      }

      if (file) {
        const body = file.encoding === 'base64' ? t('files.binary', file.bytes) : file.text
        return h('div', null,
          h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
            h(Btn, { ghost: true, onClick: () => { setFile(null); setNote(''); setError('') } }, `← ${t('files.title')}`),
            h('strong', { className: 'pwv-grow pwv-mono' }, file.path),
            file.bytes != null ? h('span', { className: 'pwv-badge' }, formatBytes(file.bytes)) : null,
            h(Btn, { onClick: () => copyLocal(file.path), disabled: busy }, t('files.copyLocal'))),
          h(ErrorLine, { text: error }),
          h(OkLine, { text: note }),
          file.encoding === 'unavailable'
            ? h('div', { className: 'pwv-muted' }, file.note)
            : file.encoding === 'base64'
              ? h('div', { className: 'pwv-muted' }, body)
              : h('pre', { className: 'pwv-pre' }, body || ''))
      }

      if (!workspace) {
        return h('div', null,
          h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
            h('strong', { className: 'pwv-grow' }, t('files.workspaces')),
            h(Btn, { ghost: true, onClick: loadWorkspaces, disabled: busy }, busy ? t('common.loading') : t('common.refresh'))),
          h(ErrorLine, { text: error }),
          !workspaces ? (busy ? h('span', { className: 'pwv-muted' }, t('common.loading')) : null)
            : workspaces.length === 0 ? h('span', { className: 'pwv-muted' }, t('files.empty'))
              : h('div', { className: 'pwv-list' },
                workspaces.map((entry) => h('button', {
                  key: entry.id,
                  type: 'button',
                  className: 'pwv-item',
                  onClick: () => { setWorkspace(entry); setError(''); setNote('') },
                },
                h('span', { className: 'pwv-mono' }, '📁'),
                h('span', { className: 'pwv-grow' }, entry.title),
                h('span', { className: 'pwv-muted pwv-mono pwv-nowrap' }, entry.path)))))
      }

      return h('div', null,
        h('div', { className: 'pwv-row', style: { marginBottom: 6 } },
          h(Btn, { ghost: true, onClick: backToWorkspaces, disabled: busy }, `← ${t('files.workspaces')}`),
          h(Btn, { ghost: true, onClick: () => load(listing ? listing.parent : '', workspace), disabled: busy || !listing || listing.path === '' }, `← ${t('files.up')}`),
          h('strong', { className: 'pwv-grow pwv-mono' }, `${workspace.title}/${listing ? listing.path || '' : ''}`),
          h('span', { className: 'pwv-badge' }, `${t('files.limit')}: ${formatBytes(listing ? listing.limitBytes : 0)}`),
          h(Btn, { ghost: true, onClick: () => load(listing ? listing.path : '', workspace), disabled: busy }, t('common.refresh'))),
        h(ErrorLine, { text: error }),
        h(OkLine, { text: note }),
        !listing ? (busy ? h('span', { className: 'pwv-muted' }, t('common.loading')) : null)
          : listing.entries.length === 0 ? h('span', { className: 'pwv-muted' }, t('files.empty'))
            : h('div', { className: 'pwv-list' },
              listing.entries.map((entry) => h('button', {
                key: entry.path,
                type: 'button',
                className: 'pwv-item',
                disabled: entry.type === 'link',
                onClick: () => (entry.type === 'dir' ? load(entry.path, workspace) : openFile(entry.path)),
              },
              h('span', { className: 'pwv-mono' }, entry.type === 'dir' ? '📁' : entry.type === 'file' ? '📄' : '🔗'),
              h('span', { className: 'pwv-grow', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, entry.name),
              entry.size != null ? h('span', { className: 'pwv-muted pwv-nowrap' }, formatBytes(entry.size)) : null))))
    }

    function ChatTab({ t, peer }) {
      const [messages, setMessages] = useState([])
      const [text, setText] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const listRef = useRef(null)

      useEffect(() => {
        if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight
      }, [messages, busy])

      if (peer.remoteTier < 3) {
        return h('div', null,
          h('div', { className: 'pwv-muted' }, t('chat.needTier')),
          h('div', { className: 'pwv-muted' }, `${t('peers.grantedToMe')}: ${peer.remoteTier >= 0 ? t(`tier.${peer.remoteTier}`) : t('tier.unknown')}`))
      }

      async function send() {
        const message = text.trim()
        if (!message || busy) return
        setText('')
        setError('')
        setMessages((current) => [...current, { role: 'user', text: message }])
        setBusy(true)
        try {
          const data = await post('remote/chat', { peerId: peer.id, message })
          setMessages((current) => [...current, { role: 'assistant', text: data.reply, meta: data.reason }])
        } catch (failure) {
          setMessages((current) => [...current, { role: 'error', text: errorLabel(t, failure) }])
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-chat', ref: listRef },
          messages.length === 0 && !busy ? h('span', { className: 'pwv-muted' }, t('chat.empty')) : null,
          messages.map((message, index) => h('div', { key: index, className: `pwv-msg ${message.role}` }, message.text)),
          busy ? h('div', { className: 'pwv-muted' }, t('chat.busy')) : null),
        h(ErrorLine, { text: error }),
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' },
            h(Input, { value: text, onChange: setText, placeholder: t('chat.placeholder'), onEnter: send, disabled: busy })),
          h(Btn, { primary: true, onClick: send, disabled: busy || !text.trim() }, busy ? t('common.loading') : t('chat.send'))))
    }

    // ------------------------------------------------------------------
    // Settings page
    // ------------------------------------------------------------------
    function SetupCard({ t, onDone }) {
      const [password, setPassword] = useState('')
      const [confirm, setConfirm] = useState('')
      const [displayName, setDisplayName] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [done, setDone] = useState('')

      async function submit() {
        setError('')
        if (password.length < 8) {
          setError(t('setup.tooShort'))
          return
        }
        if (password !== confirm) {
          setError(t('setup.mismatch'))
          return
        }
        setBusy(true)
        try {
          const data = await post('setup', { password, confirm, displayName })
          setSession(data.token, data.expiresAt)
          setDone(t('setup.done'))
          if (onDone) onDone()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', { className: 'pwv-card' },
        h('div', { className: 'pwv-title' }, t('setup.title')),
        h('div', { className: 'pwv-sub' }, t('setup.intro')),
        h(Field, { label: t('setup.password') }, h(Input, { value: password, onChange: setPassword, type: 'password', autoFocus: true })),
        h(Field, { label: t('setup.confirm') }, h(Input, { value: confirm, onChange: setConfirm, type: 'password' })),
        h(Field, { label: t('setup.displayName') }, h(Input, { value: displayName, onChange: setDisplayName })),
        h(ErrorLine, { text: error }),
        h(OkLine, { text: done }),
        h('div', { className: 'pwv-row' }, h(Btn, { primary: true, onClick: submit, disabled: busy || !password }, busy ? t('common.loading') : t('setup.submit'))))
    }

    function GrantEditor({ t, peer, onChanged }) {
      const [tier, setTier] = useState(peer.tier)
      const [password, setPassword] = useState('')
      const [pending, setPending] = useState(null)
      const [error, setError] = useState('')
      const [ok, setOk] = useState('')
      const [busy, setBusy] = useState(false)
      const [tick, setTick] = useState(Date.now())

      useEffect(() => {
        setTier(peer.tier)
      }, [peer.tier])

      useEffect(() => {
        if (!pending) return undefined
        const timer = setInterval(() => setTick(Date.now()), 250)
        return () => clearInterval(timer)
      }, [pending])

      const remaining = pending ? Math.max(0, Math.ceil((pending.earliestAt - tick) / 1000)) : 0
      const needsDelay = Number(tier) === 3 && peer.tier !== 3
      const changed = Number(tier) !== peer.tier

      useEffect(() => {
        setPending(null)
        setError('')
        setOk('')
      }, [tier])

      async function review() {
        if (!password) {
          setError(t('grant.needsPassword'))
          return
        }
        setBusy(true)
        setError('')
        setOk('')
        try {
          const data = await post('permission/prepare', { peerId: peer.id, tier: Number(tier), password })
          setPending(data)
          setTick(Date.now())
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      async function confirm() {
        if (!pending || !password) return
        setBusy(true)
        setError('')
        try {
          await post('permission/commit', { peerId: peer.id, tier: Number(tier), nonce: pending.nonce, password })
          setPending(null)
          setPassword('')
          setOk(t('grant.applied'))
          if (onChanged) onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-label', style: { marginTop: 6 } }, t('grant.title')),
        h('div', { className: 'pwv-row' },
          h('select', { className: 'pwv-input', value: tier, onChange: (event) => setTier(Number(event.target.value)) },
            [0, 1, 2, 3].map((value) => h('option', { key: value, value }, `${value} · ${t(`tier.${value}`)}`))),
          h('div', { className: 'pwv-grow' },
            h(Input, { value: password, onChange: setPassword, type: 'password', placeholder: t('common.password'), disabled: busy })),
          h(Btn, { onClick: review, disabled: busy || !changed }, busy ? t('common.loading') : t('grant.review'))),
        needsDelay ? h('div', { className: 'pwv-warn', style: { marginTop: 6 } }, t('grant.warning')) : null,
        pending
          ? h('div', { className: 'pwv-row', style: { marginTop: 6 } },
            h(Btn, {
              primary: true,
              onClick: confirm,
              disabled: busy || remaining > 0,
            }, remaining > 0 ? t('grant.wait', remaining) : t('grant.confirm')))
          : null,
        h(ErrorLine, { text: error }),
        h(OkLine, { text: ok }))
    }

    function PeerCard({ t, peer, onChanged }) {
      const [removeOpen, setRemoveOpen] = useState(false)
      const [removePassword, setRemovePassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')

      async function connect() {
        setBusy(true)
        setError('')
        try {
          await post('peer/connect', { peerId: peer.id })
          onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      async function disconnect() {
        setBusy(true)
        setError('')
        try {
          await post('peer/disconnect', { peerId: peer.id })
          onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      async function remove() {
        if (!removePassword) return
        setBusy(true)
        setError('')
        try {
          await post('peer/remove', { peerId: peer.id, password: removePassword })
          setRemoveOpen(false)
          setRemovePassword('')
          onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', { className: 'pwv-card' },
        h('div', { className: 'pwv-row' },
          h('span', { className: `pwv-dot ${peer.connected ? 'on' : 'off'}` }),
          h('strong', { className: 'pwv-grow', style: { fontSize: 13 } }, peer.name),
          peer.connected ? h('span', { className: 'pwv-badge' }, `${t('status.connected')} · ${directionLabel(t, peer)}`) : h('span', { className: 'pwv-badge' }, t('status.offline')),
          peer.remoteTier >= 3 ? h('span', { className: 'pwv-danger-badge' }, t('tier.3')) : null),
        h('div', { className: 'pwv-muted pwv-mono' }, `${t('peers.fingerprint')}: ${peer.fingerprint}`),
        h('div', { className: 'pwv-muted' },
          `${t('peers.transport')}: ${peer.endpoint || peer.transport}${peer.relay ? ` · ${t('peers.relayRole')}: ${peer.relay.role}` : ''} · ${t('peers.lastSeen')}: ${formatTime(peer.lastSeenAt)}`),
        h('div', { className: 'pwv-muted' }, `${t('peers.grantedToMe')}: ${peer.remoteTier >= 0 ? t(`tier.${peer.remoteTier}`) : t('tier.unknown')}${peer.remoteSharedLabel ? ` · ${peer.remoteSharedLabel}` : ''}`),
        h(GrantEditor, { t, peer, onChanged }),
        h('div', { className: 'pwv-sep' }),
        h('div', { className: 'pwv-row' },
          peer.connected
            ? h(Btn, { onClick: disconnect, disabled: busy }, t('peers.disconnect'))
            : h(Btn, { onClick: connect, disabled: busy }, t('peers.connect')),
          h(Btn, { danger: true, onClick: () => setRemoveOpen(!removeOpen), disabled: busy }, t('peers.remove'))),
        removeOpen
          ? h('div', { className: 'pwv-col', style: { marginTop: 6 } },
            h('span', { className: 'pwv-muted' }, t('peers.removeConfirm')),
            h('div', { className: 'pwv-row' },
              h('div', { className: 'pwv-grow' }, h(Input, { value: removePassword, onChange: setRemovePassword, type: 'password', placeholder: t('common.password'), onEnter: remove })),
              h(Btn, { danger: true, onClick: remove, disabled: busy || !removePassword }, t('common.confirm')),
              h(Btn, { ghost: true, onClick: () => { setRemoveOpen(false); setRemovePassword('') } }, t('common.cancel'))))
          : null,
        h(ErrorLine, { text: error }))
    }

    function directionLabel(t, peer) {
      return peer.direction === 'inbound' ? t('status.inbound') : peer.direction === 'outbound' ? t('status.outbound') : ''
    }

    function InviteSection({ t, state, onChanged }) {
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [invite, setInvite] = useState(null)
      const [copied, setCopied] = useState(false)
      const [mode, setMode] = useState('direct')
      const [code, setCode] = useState('')
      const [transport, setTransport] = useState('tcp')
      const [sshTarget, setSshTarget] = useState('')
      const [sshPort, setSshPort] = useState('')
      const [dialHost, setDialHost] = useState('')
      const [dialPort, setDialPort] = useState('')
      const [joinBusy, setJoinBusy] = useState(false)
      const [joinError, setJoinError] = useState('')

      async function create() {
        if (!password) return
        setBusy(true)
        setError('')
        try {
          setInvite(await post('invite/create', { password, mode }))
          setPassword('')
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      async function join() {
        if (!code.trim()) return
        setJoinBusy(true)
        setJoinError('')
        try {
          await post('invite/accept', {
            code: code.trim(),
            transport,
            sshTarget: sshTarget.trim(),
            sshRemotePort: Number(sshPort) || undefined,
            dialHost: dialHost.trim() || undefined,
            dialPort: Number(dialPort) || undefined,
          })
          setCode('')
          setSshTarget('')
          setSshPort('')
          setDialHost('')
          setDialPort('')
          if (onChanged) onChanged()
        } catch (failure) {
          setJoinError(errorLabel(t, failure))
        } finally {
          setJoinBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-h' }, t('invite.title')),
        h('div', { className: 'pwv-sub' }, t('invite.intro')),
        h('div', { className: 'pwv-row' },
          h('span', { className: 'pwv-label' }, t('invite.mode')),
          h('select', {
            className: 'pwv-input',
            value: mode,
            onChange: (event) => setMode(event.target.value),
          },
          h('option', { value: 'direct' }, t('invite.modeDirect')),
          h('option', { value: 'relay' }, t('invite.modeRelay')))),
        mode === 'relay'
          ? h('div', { className: 'pwv-muted' },
            state.relayClient && state.relayClient.host
              ? `${t('invite.modeRelayHint')} ${state.relayClient.host}:${state.relayClient.port}`
              : t('invite.modeRelayHint'))
          : null,
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' }, h(Input, { value: password, onChange: setPassword, type: 'password', placeholder: t('common.password') })),
          h(Btn, { primary: true, onClick: create, disabled: busy || !password }, busy ? t('common.loading') : t('invite.create'))),
        h(ErrorLine, { text: error }),
        invite
          ? h('div', { className: 'pwv-col', style: { marginTop: 6 } },
            h('span', { className: 'pwv-muted' }, `${t('invite.created')} ${invite.mode === 'relay' ? t('peers.relay') : t('settings.advertiseHost')}: ${invite.host}:${invite.port}`),
            h('div', { className: 'pwv-code' }, invite.code),
            h('div', { className: 'pwv-row' },
              h(Btn, { onClick: () => { setCopied(copyText(invite.code)); setTimeout(() => setCopied(false), 1500) } }, copied ? t('common.copied') : t('common.copy'))))
          : null,
        h('div', { className: 'pwv-h' }, t('invite.join')),
        h('div', { className: 'pwv-col' },
          h('textarea', {
            className: 'pwv-input',
            rows: 3,
            value: code,
            placeholder: t('invite.code'),
            onChange: (event) => setCode(event.target.value),
          }),
          h('div', { className: 'pwv-row' },
            h('label', { className: 'pwv-muted' }, h('input', {
              type: 'checkbox',
              checked: transport === 'ssh',
              onChange: (event) => setTransport(event.target.checked ? 'ssh' : 'tcp'),
            }), ` ${t('invite.ssh')}`)),
          transport === 'ssh'
            ? h('div', { className: 'pwv-row' },
              h('div', { className: 'pwv-grow' }, h(Input, { value: sshTarget, onChange: setSshTarget, placeholder: t('invite.sshTarget') })),
              h('div', { style: { width: 150 } }, h(Input, { value: sshPort, onChange: setSshPort, placeholder: t('invite.sshPort') })))
            : null,
          h('div', { className: 'pwv-row' },
            h('div', { className: 'pwv-grow' }, h(Input, { value: dialHost, onChange: setDialHost, placeholder: t('invite.dialHost') })),
            h('div', { style: { width: 150 } }, h(Input, { value: dialPort, onChange: setDialPort, placeholder: t('invite.dialPort') }))),
          h('div', { className: 'pwv-muted' }, t('invite.dialHint')),
          h(ErrorLine, { text: joinError }),
          h('div', { className: 'pwv-row' }, h(Btn, { onClick: join, disabled: joinBusy || !code.trim() }, joinBusy ? t('common.loading') : t('invite.joinSubmit')))))
    }

    function SharingSettings({ t, state, onChanged }) {
      const [mib, setMib] = useState(String(Math.round((state.settings.maxFileBytes || MI_B) / MI_B * 100) / 100))
      const [listenPort, setListenPort] = useState(String(state.settings.listenPort || ''))
      const [displayName, setDisplayName] = useState(state.settings.displayName || '')
      const [advertiseHost, setAdvertiseHost] = useState(state.settings.advertiseHost || '')
      const [autoConnect, setAutoConnect] = useState(Boolean(state.settings.autoConnect))
      const [bindHost, setBindHost] = useState(state.settings.bindHost || '0.0.0.0')
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [ok, setOk] = useState('')

      async function save() {
        if (!password) {
          setError(t('grant.needsPassword'))
          return
        }
        setBusy(true)
        setError('')
        setOk('')
        try {
          const bytes = Math.max(1024, Math.round(Number(mib) * MI_B))
          await post('settings/update', {
            password,
            patch: {
              maxFileBytes: bytes,
              listenPort: Number(listenPort),
              bindHost,
              displayName: displayName.trim(),
              advertiseHost: advertiseHost.trim(),
              autoConnect,
            },
          })
          setPassword('')
          setOk(t('settings.saved'))
          if (onChanged) onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-h' }, t('settings.title')),
        h('div', { className: 'pwv-row' },
          h(Field, { label: t('settings.maxFile'), hint: t('settings.maxFileHint') }, h(Input, { value: mib, onChange: setMib, type: 'number' })),
          h(Field, { label: t('settings.listenPort') }, h(Input, { value: listenPort, onChange: setListenPort, type: 'number' }))),
        h('div', { className: 'pwv-muted' }, t('net.allWorkspaces')),
        h('div', { className: 'pwv-row' },
          h(Field, { label: t('settings.displayName') }, h(Input, { value: displayName, onChange: setDisplayName })),
          h(Field, { label: t('settings.advertiseHost'), hint: t('settings.advertiseHostHint') }, h(Input, { value: advertiseHost, onChange: setAdvertiseHost }))),
        h(Field, { label: t('net.bindHost'), hint: t('net.bindHint') },
          h('select', { className: 'pwv-input', value: bindHost, onChange: (event) => setBindHost(event.target.value) },
            h('option', { value: '0.0.0.0' }, t('net.bindV4')),
            h('option', { value: '::' }, t('net.bindV6')))),
        h('label', { className: 'pwv-muted' }, h('input', { type: 'checkbox', checked: autoConnect, onChange: (event) => setAutoConnect(event.target.checked) }), ` ${t('settings.autoConnect')}`),
        h('div', { className: 'pwv-row', style: { marginTop: 6 } },
          h('div', { className: 'pwv-grow' }, h(Input, { value: password, onChange: setPassword, type: 'password', placeholder: t('common.password') })),
          h(Btn, { primary: true, onClick: save, disabled: busy }, busy ? t('common.loading') : t('common.save'))),
        h(ErrorLine, { text: error }),
        h(OkLine, { text: ok }))
    }

    function CrossNetSettings({ t, state, full, onChanged }) {
      const [reverse, setReverse] = useState(full ? { ...full.reverseSsh } : { enabled: false, target: '', bindPort: 0, extraArgs: '' })
      const [relayClient, setRelayClient] = useState(full ? { ...full.relayClient } : { host: '', port: 41338, token: '' })
      const [relayServer, setRelayServer] = useState(full ? { ...full.relayServer } : { enabled: false, port: 41338, token: '' })
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [ok, setOk] = useState('')

      useEffect(() => {
        if (!full) return
        setReverse({ ...full.reverseSsh })
        setRelayClient({ ...full.relayClient })
        setRelayServer({ ...full.relayServer })
      }, [full])

      async function save() {
        if (!password) {
          setError(t('grant.needsPassword'))
          return
        }
        setBusy(true)
        setError('')
        setOk('')
        try {
          await post('settings/update', {
            password,
            patch: {
              reverseSsh: {
                enabled: Boolean(reverse.enabled),
                target: String(reverse.target || '').trim(),
                bindPort: Number(reverse.bindPort) || 0,
                extraArgs: String(reverse.extraArgs || ''),
              },
              relayClient: {
                host: String(relayClient.host || '').trim(),
                port: Number(relayClient.port) || 41338,
                token: String(relayClient.token || ''),
              },
              relayServer: {
                enabled: Boolean(relayServer.enabled),
                port: Number(relayServer.port) || 41338,
                token: String(relayServer.token || ''),
              },
            },
          })
          setPassword('')
          setOk(t('net.saved'))
          if (onChanged) onChanged()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      const reverseStatus = state.reverseSsh
        ? `${state.reverseSsh.enabled ? (state.reverseSsh.running ? t('net.running') : t('net.stopped')) : t('common.none')}${state.reverseSsh.error ? ` · ${state.reverseSsh.error}` : ''}`
        : ''
      const relayStatus = state.relayServer
        ? `${state.relayServer.enabled ? (state.relayServer.running ? t('net.running') : t('net.stopped')) : t('common.none')}${state.relayServer.error ? ` · ${state.relayServer.error}` : ''}`
        : ''

      return h('div', { className: 'pwv-card' },
        h('div', { className: 'pwv-h' }, t('net.title')),
        h('div', { className: 'pwv-sub' }, t('net.intro')),
        full ? null : h('div', { className: 'pwv-muted' }, t('common.loading')),

        h('div', { className: 'pwv-h' }, t('net.reverse')),
        h('label', { className: 'pwv-muted' },
          h('input', {
            type: 'checkbox',
            checked: Boolean(reverse.enabled),
            onChange: (event) => setReverse({ ...reverse, enabled: event.target.checked }),
          }), ` ${t('net.reverseEnable')}`),
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' }, h(Input, { value: reverse.target, onChange: (value) => setReverse({ ...reverse, target: value }), placeholder: t('net.reverseTarget') })),
          h('div', { style: { width: 160 } }, h(Input, { value: String(reverse.bindPort || ''), onChange: (value) => setReverse({ ...reverse, bindPort: value }), type: 'number', placeholder: t('net.reverseBindPort') }))),
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' }, h(Input, { value: reverse.extraArgs, onChange: (value) => setReverse({ ...reverse, extraArgs: value }), placeholder: t('net.reverseExtra') }))),
        h('div', { className: 'pwv-muted' }, t('net.reverseHint')),
        h('div', { className: 'pwv-muted' }, reverseStatus),

        h('div', { className: 'pwv-h' }, t('net.relayClient')),
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' }, h(Input, { value: relayClient.host, onChange: (value) => setRelayClient({ ...relayClient, host: value }), placeholder: t('net.relayHost') })),
          h('div', { style: { width: 150 } }, h(Input, { value: String(relayClient.port || ''), onChange: (value) => setRelayClient({ ...relayClient, port: value }), type: 'number', placeholder: t('net.relayPort') })),
          h('div', { className: 'pwv-grow' }, h(Input, { value: relayClient.token, onChange: (value) => setRelayClient({ ...relayClient, token: value }), type: 'password', placeholder: t('net.relayToken') }))),
        h('div', { className: 'pwv-muted' }, t('net.relayClientHint')),

        h('div', { className: 'pwv-h' }, t('net.relayServer')),
        h('label', { className: 'pwv-muted' },
          h('input', {
            type: 'checkbox',
            checked: Boolean(relayServer.enabled),
            onChange: (event) => setRelayServer({ ...relayServer, enabled: event.target.checked }),
          }), ` ${t('net.relayServerEnable')}`),
        h('div', { className: 'pwv-row' },
          h('div', { style: { width: 150 } }, h(Input, { value: String(relayServer.port || ''), onChange: (value) => setRelayServer({ ...relayServer, port: value }), type: 'number', placeholder: t('net.relayPort') })),
          h('div', { className: 'pwv-grow' }, h(Input, { value: relayServer.token, onChange: (value) => setRelayServer({ ...relayServer, token: value }), type: 'password', placeholder: t('net.relayToken') }))),
        h('div', { className: 'pwv-muted' }, t('net.relayServerHint')),
        h('div', { className: 'pwv-muted' }, relayStatus),

        h('div', { className: 'pwv-row', style: { marginTop: 8 } },
          h('div', { className: 'pwv-grow' }, h(Input, { value: password, onChange: setPassword, type: 'password', placeholder: t('common.password') })),
          h(Btn, { primary: true, onClick: save, disabled: busy || !full }, busy ? t('common.loading') : t('net.save'))),
        h(ErrorLine, { text: error }),
        h(OkLine, { text: ok }),

        h('div', { className: 'pwv-guide' },
          h('div', { className: 'pwv-h' }, t('net.guide')),
          h('div', { className: 'pwv-muted' }, t('net.guideHint')),
          ['lan', 'portForward', 'customDial', 'reverseSsh', 'relay', 'ipv6', 'sshTunnel', 'tailscale', 'zerotier'].map((key) =>
            h('details', { key, className: 'pwv-tutorial' },
              h('summary', null, t(`tutorial.${key}.title`)),
              h('div', { className: 'pwv-guide-body' }, t(`tutorial.${key}.body`))))))
    }

    function PasswordSection({ t }) {
      const [current, setCurrent] = useState('')
      const [next, setNext] = useState('')
      const [confirm, setConfirm] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      const [ok, setOk] = useState('')

      async function change() {
        setError('')
        if (next.length < 8) {
          setError(t('setup.tooShort'))
          return
        }
        if (next !== confirm) {
          setError(t('setup.mismatch'))
          return
        }
        setBusy(true)
        try {
          await post('password/change', { currentPassword: current, nextPassword: next, confirm })
          setCurrent('')
          setNext('')
          setConfirm('')
          setOk(t('password.changed'))
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-h' }, t('password.title')),
        h('div', { className: 'pwv-row' },
          h(Field, { label: t('password.current') }, h(Input, { value: current, onChange: setCurrent, type: 'password' })),
          h(Field, { label: t('password.next') }, h(Input, { value: next, onChange: setNext, type: 'password' })),
          h(Field, { label: t('setup.confirm') }, h(Input, { value: confirm, onChange: setConfirm, type: 'password' }))),
        h(ErrorLine, { text: error }),
        h(OkLine, { text: ok }),
        h(Btn, { onClick: change, disabled: busy }, busy ? t('common.loading') : t('password.change')))
    }

    function DangerSection({ t, onReset }) {
      const [open, setOpen] = useState(false)
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')

      async function reset() {
        if (!password) return
        setBusy(true)
        setError('')
        try {
          await post('reset', { password })
          setSession(null, 0)
          setOpen(false)
          setPassword('')
          if (onReset) onReset()
        } catch (failure) {
          setError(errorLabel(t, failure))
        } finally {
          setBusy(false)
        }
      }

      return h('div', null,
        h('div', { className: 'pwv-h' }, t('reset.title')),
        h('div', { className: 'pwv-warn' }, t('reset.warning')),
        !open
          ? h('div', { className: 'pwv-row', style: { marginTop: 6 } }, h(Btn, { danger: true, onClick: () => setOpen(true) }, t('reset.title')))
          : h('div', { className: 'pwv-row', style: { marginTop: 6 } },
            h('div', { className: 'pwv-grow' }, h(Input, { value: password, onChange: setPassword, type: 'password', placeholder: t('common.password'), onEnter: reset })),
            h(Btn, { danger: true, onClick: reset, disabled: busy || !password }, busy ? t('common.loading') : t('reset.submit')),
            h(Btn, { ghost: true, onClick: () => { setOpen(false); setPassword(''); setError('') } }, t('common.cancel'))),
        h(ErrorLine, { text: error }))
    }

    function AuditList({ t, audit }) {
      return h('div', null,
        h('div', { className: 'pwv-h' }, t('audit.title')),
        !audit || audit.length === 0
          ? h('div', { className: 'pwv-muted' }, t('audit.empty'))
          : h('div', { className: 'pwv-list' },
            audit.map((entry, index) => h('div', { key: index, className: 'pwv-row' },
              h('span', { className: 'pwv-muted pwv-nowrap' }, formatTime(entry.time)),
              h('span', { className: 'pwv-grow pwv-mono' }, entry.kind),
              h('span', { className: 'pwv-muted pwv-mono' }, entry.detail)))))
    }

    function SettingsPage({ ctx, close }) {
      const t = useT(ctx)
      const current = useSession()
      const { state, error, reload } = usePublic(true, 3000)
      const [full, setFull] = useState(null)
      const loadFull = useCallback(async () => {
        if (!current.token) {
          setFull(null)
          return
        }
        try {
          setFull(await post('settings/read', {}))
        } catch {
          setFull(null)
        }
      }, [current.token])
      useEffect(() => {
        if (current.token) loadFull()
        else setFull(null)
      }, [current.token, loadFull])
      const refreshAll = () => {
        reload()
        loadFull()
      }

      if (!state) {
        return h('div', { className: 'pwv-root', style: { padding: 12 } }, h(Styles),
          h('div', { className: 'pwv-muted' }, error === 'network' ? t('error.network') : t('common.loading')))
      }

      if (!state.passwordSet) {
        return h('div', { className: 'pwv-root', style: { padding: 4 } }, h(Styles),
          h(SetupCard, { t, onDone: reload }))
      }

      return h('div', { className: 'pwv-root', style: { padding: '2px 2px 24px' } },
        h(Styles),
        h('div', { className: 'pwv-row' },
          h('div', { className: 'pwv-grow' },
            h('div', { className: 'pwv-title' }, t('section.title')),
            h('div', { className: 'pwv-sub' }, t('section.description'))),
          state.unlocked
            ? h(Btn, { onClick: async () => { await post('lock', {}); setSession(null, 0); reload() } }, t('status.locked'))
            : null),
        error ? h(ErrorLine, { text: error === 'network' ? t('error.network') : error }) : null,
        !state.unlocked
          ? h('div', { className: 'pwv-card' },
            h('div', { className: 'pwv-title' }, t('unlock.title')),
            h('div', { className: 'pwv-sub' }, t('unlock.intro')),
            h(UnlockForm, { t, onDone: reload }),
            h(ForceResetCard, { t, onDone: reload }))
          : !current.token
            ? h('div', { className: 'pwv-card' },
              h('div', { className: 'pwv-title' }, t('unlock.title')),
              h(UnlockForm, { t, onDone: reload }))
            : null,
        state.unlocked && current.token
          ? h('div', null,
            h('div', { className: 'pwv-card' },
              h('div', { className: 'pwv-row' },
                h('span', { className: 'pwv-mono pwv-grow' }, `${t('peers.fingerprint')}: ${state.fingerprint}`),
                h('span', { className: 'pwv-badge' }, state.listening.active ? `${t('status.connected')} :${state.listening.port}` : t('status.offline'))),
              state.serverError ? h('div', { className: 'pwv-err' }, state.serverError) : null,
              h('div', { className: 'pwv-muted' }, `${t('settings.sharedRoot')}: ${state.settings.sharedRoot}`),
              h('div', { className: 'pwv-muted' }, `${t('files.limit')}: ${formatBytes(state.settings.maxFileBytes)} · ${t('settings.listenPort')}: ${state.listening.port} · ${t('settings.advertiseHost')}: ${state.listening.advertisedHost}`)),
            h('div', { className: 'pwv-h' }, t('peers.title')),
            state.peers.length === 0
              ? h('div', { className: 'pwv-muted' }, t('peers.empty'))
              : state.peers.map((peer) => h(PeerCard, { key: peer.id, t, peer, onChanged: reload })),
            h(InviteSection, { t, state, onChanged: refreshAll }),
            h(SharingSettings, { t, state, onChanged: refreshAll }),
            h(CrossNetSettings, { t, state, full, onChanged: refreshAll }),
            h(PasswordSection, { t }),
            h(AuditList, { t, audit: state.audit }),
            h(DangerSection, { t, onReset: reload }))
          : null)
    }

    // ------------------------------------------------------------------
    // Apply
    // ------------------------------------------------------------------
    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        try {
          ctx.effect(
            () => ctx.locale.register(NS, { en: EN, zh: ZH }),
            'peerweave: dictionaries',
          )
        } catch (error) {
          console.error('[peerweave] locale registration failed', error)
        }
        const t = ctx.locale.bind(NS)
        try {
          ctx.effect(
            () => ctx.slots.register(
              {
                name: 'settings.section',
                id: 'peerweave',
                order: 60,
                label: () => t('section.title'),
                locale: NS,
              },
              (props) => h(SettingsPage, { ctx, close: props && props.close }),
            ),
            'peerweave: settings section',
          )
        } catch (error) {
          console.error('[peerweave] settings section registration failed', error)
        }
        try {
          ctx.effect(
            () => ctx.slots.register(
              {
                name: 'conversation.composer.dock',
                id: 'peerweave-dock',
                order: 20,
                locale: NS,
              },
              () => h(Dock, { ctx }),
            ),
            'peerweave: workspace dock',
          )
        } catch (error) {
          console.error('[peerweave] dock registration failed', error)
        }
        try {
          ctx.effect(
            () => ctx.slots.register(
              {
                name: 'sidebar.footer.action',
                id: 'peerweave',
                order: -15,
                locale: NS,
              },
              (props) => h(PeerSidebarEntry, { ctx, wide: props && props.wide }),
            ),
            'peerweave: sidebar entry',
          )
        } catch (error) {
          console.error('[peerweave] sidebar entry registration failed', error)
        }
        try {
          ctx.effect(
            () => ctx.slots.register(
              {
                name: 'shell.overlay',
                id: 'peerweave-browser',
                order: 30,
                locale: NS,
              },
              () => h(PeerOverlay, { ctx }),
            ),
            'peerweave: overlay browser',
          )
        } catch (error) {
          console.error('[peerweave] overlay registration failed', error)
        }
      },
    }
  },
})
