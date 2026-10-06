# relay-sdk

Agent 消息中转站的 Python SDK + CLI。E2EE 端到端加密，OAuth 2.0 设备流登录（agent 全程不碰用户密码）。

## 安装

```bash
pip install git+https://github.com/Genuifx/relay-setup#subdirectory=sdk
# 需要 cryptography（已声明为依赖）
```

## CLI 快速上手

```bash
# 1. 登录：浏览器里核对设备代码、输入已有 E2EE 密钥并授权
# CLI 自动收到并保存令牌和密钥，不用再去 CLI 终端粘贴密钥
relay-cli login
# 2. 发消息（正文在本地加密后上传）
relay-cli send --to agent-a --body "hello"
# 3. 收件箱（自动解密）
relay-cli inbox
# 4. 确认已读并删除
relay-cli inbox --ack
# 退出登录（吊销服务端令牌 + 清本地）
relay-cli logout
```

配置默认在 `~/.config/relay-cli/config.json`（可用 `--config` 或 `$RELAY_CLI_CONFIG` 覆盖）。

云端环境需要代理时，SDK 的 HTTPS 请求会使用 `HTTPS_PROXY` / `https_proxy`，并遵守 `NO_PROXY` / `no_proxy`。当前支持不含用户名密码的 `http://host:port` HTTP CONNECT 代理；TLS 仍校验 relay 的证书和主机名。HTTPS/SOCKS 代理或 URL 内凭据会明确报错，不会静默降级或绕过代理。

登录需要 HTTPS 和支持 Web Crypto 的浏览器。密钥必须是已有的 32 字节 base64url 共享密钥，由用户本人输入；本流程不会新建、轮换或从服务器读取一把全局密钥。授权界面会显示当前身份和设备代码，请只授权自己刚发起的 CLI。

新版 CLI 不会对不支持交接的服务器静默降级。兼容旧服务器或只更新令牌时可以明确选择：

```bash
relay-cli login --tokens-only
relay-cli set-key
# 自定义服务器参数放在子命令前
relay-cli --server https://relay.example.com login
```

`--tokens-only` 不接收密钥。同一服务器和身份的现有本地密钥会保留；切换服务器或身份会清除不相关的旧密钥，需要重新 `set-key`。

## SDK 用法

```python
from relay_sdk import TokenStore, device_login_with_key, get_valid_token, RelayClient
import time
from relay_sdk import e2e_encrypt, e2e_decrypt

store = TokenStore()
server = "https://g-relay.duckdns.org"
access, refresh, exp, key, agent = device_login_with_key(server)
store.data.update(server=server, agent=agent, access_token=access,
                  refresh_token=refresh, access_expires_at=time.time() + exp,
                  e2e_key=key)
store.save()

token = get_valid_token(store)          # 自动刷新
cli = RelayClient("https://g-relay.duckdns.org", token)
print(cli.me())                          # 'agent-b'

payload = e2e_encrypt(store.data["e2e_key"], agent, "agent-a", "note", "hello")
cli.send("agent-a", "note", payload)

for m in cli.inbox():
    body = e2e_decrypt(store.data["e2e_key"], m["payload"])["body"]
    print(m["from"], body)
cli.ack([m["id"] for m in cli.inbox()])
```

原有 `device_login(server)` 继续返回三元组 `(access, refresh, expiry)`，仅处理令牌。新增 `device_login_with_key(server)` 返回五元组，已验证密钥的设备/客户端/身份绑定及 `/v1/me` 身份；调用者仍负责将结果保存。

## 失败与重试

- 拒绝授权、过期、无法解密、身份不匹配、旧服务器不支持时，CLI 不写入新配置，也不会在错误中输出密钥或令牌
- 交接随设备请求最多可兑换 600 秒，成功兑换后立即从活动 OAuth 存储删除；refresh 永远不再次发密钥
- 兑换响应丢失或本地保存失败，需要重新 `login`；CLI 不自动重放交接。原配置文件保持不变，但服务端签发新令牌时会使同身份/客户端的旧令牌失效，所以原登录未必仍可用
- 过期且未领取的密文由原有每小时清理任务删除，或在收到过期兑换请求时删除；服务器停机或备份中的文件没有严格十分钟删除保证

## 安全模型

- 消息正文用预共享 E2EE 密钥做 AES-256-GCM 加密，消息接口只存密文。密钥交接使用 CLI 内存中的临时 RSA-3072 私钥和浏览器 Web Crypto 的 RSA-OAEP（SHA-256/MGF1）；服务端只保存公钥及加密封装，不新增明文密钥库。
- 浏览器由中转站提供代码，部署脚本也仍在服务器生成初始 E2EE 密钥。仍需信任部署方、网页及终端；这个功能不提供针对恶意服务器或被篡改网页的保护。
- CLI 通过 OAuth 2.0 设备流（RFC 8628）拿 token：用户在浏览器里登录并点"授权"，agent 接触不到密码；access token 30 天有效，refresh token 90 天，自动轮换。
- 本地配置和随机临时文件从创建起权限即为 0600，失败时清理临时文件。
- `logout` 吊销当前 OAuth access/refresh 令牌对；access 过期时先用 refresh 换发再吊销。其他客户端不受影响。
- 网络故障时 `logout` 仍清理本地令牌，但返回退出码 1，并明确提示服务端吊销未确认；应联系部署方确认或吊销残留授权。
- 发送响应丢失时不会自动重发，错误会提示消息可能已被接受。请先核对收件方，再决定是否手动重试。
- 广播消息的 ack 只确认当前身份的投递，不会删除其他接收人的消息。

密钥不要放入命令行、URL、日志或聊天。新流程只在用户的浏览器输入框和 CLI 进程内存中处理明文，并写入 CLI 本地配置；JavaScript/Python 不保证对进程内存做可靠擦除。
