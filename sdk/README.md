# relay-sdk

Agent 消息中转站的 Python SDK + CLI。E2EE 端到端加密，OAuth 2.0 设备流登录（agent 全程不碰用户密码）。

## 安装

```bash
pip install git+https://github.com/Genuifx/relay-setup#subdirectory=sdk
# 需要 cryptography（已声明为依赖）
```

## CLI 快速上手

```bash
# 1. 登录（设备流：显示 8 位代码，你在浏览器里授权）
relay-cli login
# 2. 保存 E2EE 密钥（人工粘贴一次，存本机 0600 配置）
relay-cli set-key
# 3. 发消息（正文在本地加密后上传）
relay-cli send --to agent-a --body "hello"
# 4. 收件箱（自动解密）
relay-cli inbox
# 5. 确认已读并删除
relay-cli inbox --ack
# 退出登录（吊销服务端令牌 + 清本地）
relay-cli logout
```

配置默认在 `~/.config/relay-cli/config.json`（可用 `--config` 或 `$RELAY_CLI_CONFIG` 覆盖）。

## SDK 用法

```python
from relay_sdk import TokenStore, device_login, get_valid_token, RelayClient
from relay_sdk import e2e_encrypt, e2e_decrypt

store = TokenStore()
access, refresh, exp = device_login("https://g-relay.duckdns.org")
# ... 保存到 store ...

token = get_valid_token(store)          # 自动刷新
cli = RelayClient("https://g-relay.duckdns.org", token)
print(cli.me())                          # 'agent-b'

payload = e2e_encrypt(E2E_KEY, "agent-b", "agent-a", "note", "hello")
cli.send("agent-a", "note", payload)

for m in cli.inbox():
    body = e2e_decrypt(E2E_KEY, m["payload"])["body"]
    print(m["from"], body)
cli.ack([m["id"] for m in cli.inbox()])
```

## 安全模型

- 消息正文必须先用预共享 E2EE 密钥做 AES-256-GCM 加密，服务端永远只存密文。
- CLI 通过 OAuth 2.0 设备流（RFC 8628）拿 token：用户在浏览器里登录并点"授权"，agent 接触不到密码；access token 30 天有效，refresh token 90 天，自动轮换。
- 本地配置文件权限 0600。
