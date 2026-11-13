# Peerweave 连接教程（全部方式）

本文件覆盖 Peerweave 目前支持的每一种连接方式。插件 设置 → Peerweave → 跨公网连接 里也内置了同样的精简步骤。

> 通用前提：两端都安装 Peerweave、重启 DSH、刷新页面、创建密码并解锁；A 是生成邀请码的一方，B 是加入的一方。邀请码 10 分钟内有效、只能使用一次；配对后双方默认第 0 档（仅链接），需要各自设置「我授予对方的权限」。

---

## 0. 先认识三种地址

| 名称 | 在哪里设置 | 作用 |
|---|---|---|
| 监听地址 / 监听端口 | 共享设置 | 本机 DSH 实际监听的位置，默认 `0.0.0.0:41337`，可改 IPv6 双栈 `::` |
| 供对方连接的地址 | 共享设置 | 写进邀请码、让 B 拨号的地址；空 = 自动检测局域网 IPv4 |
| 自定义拨号地址/端口 | 加入邀请码时 | 仅 B 使用，覆盖邀请码内的地址；用于 ngrok、frp、端口不一致等 |

> 注意：如果 A 开启了「反向 SSH」，所有「直连」邀请码都会使用 VPS 地址/VPS 端口。想走局域网、Tailscale、ZeroTier 或普通端口映射时，请先关闭反向 SSH，或在 B 加入时用「自定义拨号地址/端口」覆盖。

---

## 1. 局域网直连

适用：两台电脑在同一 Wi‑Fi、交换机或同一 VLAN。

1. A、B 都设置密码并解锁。
2. A：共享设置 → 监听地址 `IPv4 only (0.0.0.0)`，端口 `41337`。
3. A：「供对方连接的地址」留空（自动使用局域网 IPv4）。如果 A 有多个网卡导致自动检测不对，手填 A 的局域网 IP（如 `192.168.1.10`）。
4. A：邀请 → 方式「直连/反向 SSH」→ 生成邀请码。
5. B：粘贴邀请码 → 加入。
6. 若连接失败，在 A 的防火墙放行 TCP 41337：

   Windows（管理员 PowerShell）：

   ```powershell
   New-NetFirewallRule -DisplayName "Peerweave" -Direction Inbound -Protocol TCP -LocalPort 41337 -Action Allow
   ```

   Linux：

   ```bash
   sudo ufw allow 41337/tcp
   ```

7. 配对成功后，在两端设置权限档位。

验证：在 B 上执行 `Test-NetConnection 192.168.1.10 -Port 41337`（Windows）或 `nc -vz 192.168.1.10 41337`。

---

## 2. 公网 IPv4 + 端口映射

适用：A 有公网 IPv4（或 DDNS），B 在任意网络。

1. 给 A 固定局域网 IP（路由器 DHCP 静态绑定），例如 `192.168.1.10`。
2. 路由器端口转发：外部 TCP `41337` → `192.168.1.10:41337`。
3. A 的系统防火墙放行 TCP 41337（命令同上）。
4. A：共享设置 →「供对方连接的地址」填公网 IP 或 DDNS 域名（如 `home.example.com`）。
5. A：生成「直连」邀请码；B 加入。
6. 用手机热点（不要连同一 Wi‑Fi）测试，确认走的是公网。

**CGNAT 判断**：路由器 WAN 口 IP 与 `curl ifconfig.me` 得到的公网 IP 不一致，或 WAN IP 在 `100.64.0.0/10`、`10/8`、`172.16/12`、`192.168/16` 内，说明没有真正公网 IPv4，端口映射无效。改用 Tailscale / ZeroTier、反向 SSH 或中继。

---

## 3. 自定义拨号地址/端口

适用：邀请码里的地址不可达，或对外端口与 A 的监听端口不同。

1. 先准备好通道（任选）：
   - ngrok：`ngrok tcp 41337`，得到 `tcp://0.tcp.ngrok.io:12345`；
   - frp：VPS 上 `remotePort = 41337`，A 本地 `localPort = 41337`；
   - 反向 SSH：见第 4 节；
   - 家用路由器端口映射到不同外部端口。
2. A：正常生成「直连」邀请码（邀请码里的地址可以留空/内网地址）。
3. B：加入时填写：
   - 自定义拨号地址：真实公网入口，如 `0.tcp.ngrok.io`；
   - 自定义拨号端口：如 `12345`。
4. 留空则使用邀请码里的地址。

说明：只改变 B 的拨号目标，邀请码里的 Ed25519 指纹仍然校验 A 的身份；自定义地址会写入节点记录，断线重连继续使用。SSH 模式下「自定义拨号端口」会作为 SSH 远端端口使用。

---

## 4. 反向 SSH（A 在 NAT 后）

适用：A 在 NAT/CGNAT 后，但 A 能主动 SSH 到一台公网 VPS。

### 4.1 VPS 准备

```bash
sudo nano /etc/ssh/sshd_config
```

确认/添加：

```
GatewayPorts clientspecified
AllowTcpForwarding yes
```

```bash
sudo systemctl restart ssh
sudo ufw allow 41337/tcp   # 或你选择的对外端口
```

> `GatewayPorts` 必须是 `clientspecified` 或 `yes`，否则 `-R 0.0.0.0:...` 只在 VPS 回环监听，B 连不上。

### 4.2 A 设置

1. 设置 → Peerweave → 跨公网连接 → 反向 SSH：
   - 勾选「主动向 VPS 建立 ssh -R 隧道」；
   - SSH 目标：`user@vps.example.com`；
   - VPS 上对外暴露的端口：`41337`；
   - 额外参数可留空；需要非 22 端口时填 `-p 2222`。
2. 「供对方连接的地址」填 VPS 域名或 IP。
3. 保存（需密码），等待状态显示 **running**。插件实际执行：

   ```
   ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \
       -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
       -o StrictHostKeyChecking=accept-new \
       -R 0.0.0.0:41337:127.0.0.1:41337 user@vps.example.com
   ```

4. A 生成「直连」邀请码，此时邀请码的 host 是 VPS、port 是 VPS 端口。
5. B 直接加入。

### 4.3 排查

- 状态行里会显示 ssh 最近错误。
- VPS 上执行 `ss -ltnp | grep 41337` 确认监听。
- B 上 `nc -vz vps.example.com 41337`。
- 密钥需要非交互登录：使用 ssh-agent，或专用无口令 key；不要依赖手输密码（`BatchMode=yes`）。
- VPS 的安全组/防火墙也要放行。

---

## 5. 内置中继（NAT 到 NAT）

适用：两端都在 NAT/CGNAT 后，且有一台公网 VPS；两端都不需要可达端口。

### 5.1 在 VPS 启动中继

```bash
git clone https://github.com/GGGinnnnn/dsh-peerweave.git
cd dsh-peerweave
node relay.js --port 41338 --token "$(node -e 'console.log(require("crypto").randomBytes(24).toString("hex"))')"
```

或安装后使用 bin：`dsh-peerweave-relay --port 41338 --token ...`。

放行 VPS TCP 41338。推荐用 systemd：

```ini
[Unit]
Description=Peerweave relay
After=network.target

[Service]
WorkingDirectory=/opt/dsh-peerweave
ExecStart=/usr/bin/node /opt/dsh-peerweave/relay.js --port 41338 --token YOUR_TOKEN
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now peerweave-relay
```

### 5.2 A 设置

1. 设置 → Peerweave → 跨公网连接 → 中继客户端：填 VPS 地址、41338、token。
2. 保存后，邀请 → 方式选「中继（NAT 到 NAT）」→ 生成邀请码。
3. A 会主动连中继并等待 B。

### 5.3 B 加入

1. B 只需解锁 Peerweave，粘贴邀请码加入。
2. B 会主动连中继；两端到齐后中继回 `OK`，Peerweave 在密文上完成握手。
3. 配对后节点记录保存中继房间，断线自动重连。

排查：VPS 上 `nc -vz vps 41338`；token 必须一致；中继日志只显示房间前缀，不显示内容。中继可被 DoS，建议启用 token 并只对可信网络开放。

---

## 6. IPv6 / 双栈

适用：两端都有可用 IPv6（公网 IPv6 或同一 IPv6 内网）。

1. A：共享设置 → 监听地址 = `IPv6 + IPv4 dual-stack (::)`。
2. 防火墙放行监听端口（IPv6 规则）。
3. A：「供对方连接的地址」填 A 的 IPv6 字面量，例如 `2408:8207:...`，**不要加方括号**。
4. A 生成「直连」邀请码；B 加入。
5. 验证：
   - Windows：`ping -6 2408:...`、`Test-NetConnection 2408:... -Port 41337`
   - Linux/macOS：`ping6 2408:...`、`nc -6 -vz 2408:... 41337`

注意：监听 `::` 默认双栈（Windows 上接受 IPv4 映射）；如果系统/防火墙禁用了 IPv6，切回 `0.0.0.0`。本仓库的自动测试环境禁止 `::1` 连接，因此只验证了双栈绑定和 IPv4 半边，真实 IPv6 需在你的网络测试。

---

## 7. SSH 隧道（B 到 A）

适用：B 能 SSH 到 A，但不想在 A 上开放 Peerweave 端口。

1. A 运行 sshd；A 的 DSH 监听 `41337`。
2. A 正常生成邀请码（地址可以是内网地址）。
3. B：加入时勾选「通过 SSH 隧道」，填：
   - SSH 目标：`user@A`（A 的公网/可达地址）；
   - SSH 主机上的端口：`41337`。
4. 插件执行：

   ```
   ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \
       -o StrictHostKeyChecking=accept-new \
       -L 127.0.0.1:<临时端口>:127.0.0.1:41337 user@A
   ```

5. 密钥：带口令的 key 需要先 `ssh-add` 到 ssh-agent；建议在 VPS/A 的 `authorized_keys` 限制用途：

   ```
   command="/bin/false",permitopen="127.0.0.1:41337" ssh-ed25519 AAAA...
   ```

限制：SSH 目标必须是运行 DSH 的那台机器（`-L` 转到 SSH 主机的 loopback）。如果只有跳板机能访问 A，当前模式不适用，请用反向 SSH 或中继。

---

## 8. Tailscale 组网

适用：两台机器离得远、在 CGNAT 后，或不想维护端口映射/中继。

1. 两台电脑安装 Tailscale：<https://tailscale.com/download>。
2. 都登录同一账号（同一 tailnet）。
3. 确认在线：

   ```bash
   tailscale status
   tailscale ip -4
   ```

4. 记下 A 的 `100.x.y.z` 地址（或 MagicDNS 名称，如 `a-laptop.tailnet-name.ts.net`）。
5. A：共享设置 →「供对方连接的地址」填该地址；生成「直连」邀请码。
6. B：加入邀请码。
7. 直连失败会自动走 DERP 中继，Peerweave 仍然端到端加密。
8. 建议用 Tailscale ACL/tag 限制哪些设备能访问 A 的 41337 端口。

验证：B 上 `tailscale ping A`、`nc -vz 100.x.y.z 41337`。

---

## 9. ZeroTier 组网

适用：同 Tailscale，适合已有 ZeroTier 网络的用户。

1. 在 <https://my.zerotier.com> 创建 Network。
2. 两台电脑安装 ZeroTier 并加入：

   ```bash
   zerotier-cli join <NETWORK_ID>
   ```

3. 在 ZeroTier 控制台勾选授权两台设备。
4. 查 A 的 Managed IP：

   ```bash
   zerotier-cli listnetworks
   ```

5. A：共享设置 →「供对方连接的地址」填该 Managed IP；生成「直连」邀请码。
6. B：加入邀请码。
7. 保持网络私有；Managed IP 只有被授权成员能访问。

---

## 10. 配对后的使用（三档权限）

| 档位 | 对方可以 | 对方不可以 |
|---|---|---|
| 0 仅链接 | 看到名称/指纹/在线状态 | 读写任何内容 |
| 1 查看工作区 | 列出并读取**全部已注册工作区**内的会话历史（未归档/已归档分组） | 读文件、对话 |
| 2 读取文件 | 先列出对方全部工作区，再浏览/读取文件、复制到对方电脑继续工作；请求对方总结记忆并导入 | 修改、删除、写入你的文件 |
| 3 与 DSH 对话 | 在全屏 DSH 对话里与真实 Agent 对话，可切回浏览模式继续第二档操作 | 改模型、改权限、绕过密码 |

- **入口**：左侧栏底部有 Peerweave 按钮；只有一个节点时按钮直接显示该节点名称。点开后是「节点 → 工作区 → 会话」浏览器，不需要在设置里选择共享目录。
- **读取对话**：历史列表每一行右侧有「读取」；进入后可以看完整消息。默认只显示未归档会话，顶部「已归档 (N)」可展开已归档会话。
- **读取记忆并导入**：在节点顶部、工作区标题或某个会话里点「读取记忆」，选择 1000–50000 字，点「读取并导入」。对方 DSH 用自己的默认模型总结，本机自动新建工作区 `Peerweave memory · <节点名>`、复制摘要中的相关文件到 `files/`，并把记忆导入新对话。记忆按不可信文本处理。
- **第三档全屏对话**：对方授予第三档后，打开节点默认进入「DSH 对话」，可以直接对话；顶部「浏览」切回历史/文件界面。对方模型和权限只读显示，不能从本机修改；对话仍走对方的工作区和权限。
- 设置里的「共享工作区根目录」已移除；历史按对方注册的全部工作区分组，文件浏览先列出工作区，再进入目录。
- 修改档位需要输入密码；第 3 档必须等满 10 秒（服务端强制）。
- 文件大小由文件提供方设置，默认 16 MiB，硬上限 2 GiB；超过 8 MiB 的文件不能内联预览，用「复制到我的工作区」走 8 MiB 分块传输。
- 对话在对方机器上运行真实 Agent，消耗对方的模型 token；本机 Chat 面板本身不消耗本机 token。
- 浏览对方历史/文件是本地 UI 数据，**0 token**；只有本机 Agent 调用 `peerweave_history` / `peerweave_read_file` 才会把内容放进上下文。

> 原生左侧「工作区」分组由 DSH 宿主管理，插件插槽没有提供“添加远程工作区分组”的入口；Peerweave 用左侧底部入口 + 全屏工作区浏览器实现同样的导航，避免替换整个侧边栏造成升级失效。如果你希望它伪装成本地工作区分组，只能替换 `sidebar.workspaces` 整个组件，风险很高，不建议。

---

## 11. 故障排查速查

| 现象 | 检查 |
|---|---|
| `unknown-peer` / 握手被拒 | 邀请码过期/用过；对方指纹变化；重新生成邀请码 |
| `connect-failed` / 超时 | 地址端口是否可达；防火墙/安全组；CGNAT；`nc -vz` |
| `invite-expired` | 邀请码 10 分钟有效，重新生成 |
| 反向 SSH 状态 error | VPS `GatewayPorts clientspecified`；VPS 防火墙；ssh 密钥/agent；`ss -ltnp` |
| 中继连不上 | VPS 41338 是否放行；token 是否一致；`relay.js` 是否运行 |
| `ssh` 找不到 | Windows 安装 OpenSSH Client；或配置 `sshCommand` |
| 端口占用 | 换监听端口；状态会显示实际端口 |
| IPv6 连不上 | 两端 IPv6 路由/防火墙；地址不要加方括号；先 `ping6` |
| 中继房间冲突/角色被占 | 等待旧连接超时（120 秒）；或移除节点重新配对 |
| 忘记密码 | 锁定页「强制清除 Peerweave…」，等 10 秒确认；或删除状态文件 |

---

## 12. 安全建议

- 只暴露 Peerweave 监听端口，不要暴露 DSH Web 端口（默认 13310）。
- 公网直连优先限制来源 IP；否则优先 Tailscale/ZeroTier/SSH/中继。
- 中继启用 token；邀请码只通过可信渠道发送。
- 反向 SSH 使用专用、可限制的 SSH key；VPS 开启防火墙。
- 第 3 档等于把本机 Agent 的控制权交给对方，只授予完全信任的人。
- 状态文件包含加密身份、节点、中继 token/房间等，按敏感文件保护并备份。
