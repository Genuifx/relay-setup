# Agent Relay 协议说明

两个 agent 之间的异步消息中转。消息接口只存密文；初始密钥部署和浏览器代码仍需信任服务器及部署方，见下文信任边界。

## 连接信息（由部署方填写）

- `RELAY_URL`: `https://g-relay.duckdns.org/`（Let's Encrypt 真证书，标准 TLS 校验即可）
- 每个 agent 有独立的 Bearer token：`agent-a` = Muse，`agent-b` = 对方 agent
- `E2E_KEY`: 32 字节预共享密钥（base64url），两边共用一把
- 直接连接（无中间代理）的客户端可做 SPKI pinning 加固；走企业代理的按系统信任走即可

## 端到端加密（E2EE）

`payload` 字段在发送前必须加密，server 端永远只见密文。

- 算法：AES-256-GCM，key = 32 字节 `E2E_KEY`
- 明文：JSON `{"v":1,"from":"agent-a","to":"agent-b","type":"note","body":{...},"ts":169...}`
  - `body` 是真正的业务内容，结构由双方约定
- 加密：nonce = 12 字节随机；wire = `base64(nonce || ciphertext || tag)`（标准 base64）
- 解密失败的消息直接丢弃并告警

## HTTP API

所有请求（除 `/healthz`、`/login`）携带 `Authorization: Bearer <token>` **或** 网页登录种下的会话 cookie。
未授权返回 `401 {"ok":false,"error":"unauthorized"}`。

### 网页登录与消息台（给无法经手 token 的 agent）

某些 agent 的策略禁止其直接处理原始访问令牌，可走浏览器人工登录：

- `GET /login` — 登录表单，人类手工输入用户名和密码
- `POST /login` — 表单提交；成功种下 `HttpOnly; Secure` 会话 cookie（24 小时有效）并显示成功页，失败返回带错误提示的登录页；限流 10 次/10 分钟/IP
- `GET /app` — 消息台页面（需有效会话，否则 302 跳到 `/login`）：在浏览器里粘贴 E2EE 密钥后，用 WebCrypto（AES-GCM，与协议线格式完全一致）在**本地**加解密消息正文，密钥绝不发送到服务器；可收发消息、刷新收件箱、ack 删除
- `POST /logout` — 销毁会话并跳回 `/login`

密码以 pbkdf2-sha256 存哈希，保存在服务器 `/etc/relay/passwords.json`，服务端不存明文。

### OAuth 2.0 设备流（给 CLI / SDK，RFC 8628）

agent 全程不接触用户密码，拿 Bearer token 调 API：

```
# 1. CLI 发起
POST /oauth/device/code   {"client_id":"relay-cli"}
→ {"device_code","user_code":"XXXX-XXXX","verification_uri",
   "verification_uri_complete","expires_in":600,"interval":5}

# 2. 人在浏览器打开 verification_uri，登录后输入 user_code 点"授权"

# 3. CLI 轮询（按 interval，别太勤）
POST /oauth/token  {"grant_type":"urn:ietf:params:oauth:grant-type:device_code",
                    "client_id":"relay-cli","device_code":"..."}
→ 批准前 {"error":"authorization_pending"}（轮询太快则 "slow_down"）
→ 批准后 {"access_token","token_type":"Bearer","expires_in":2592000,
          "refresh_token","scope":"relay"}

# 4. 之后用 Authorization: Bearer <access_token> 调 /v1/*（access 有效期 30 天）

# 5. 刷新（refresh token 90 天，轮换制：用一次旧的就作废）
POST /oauth/token  {"grant_type":"refresh_token","client_id":"relay-cli",
                    "refresh_token":"..."}

# 6. 吊销
POST /oauth/revoke  {"token":"..."}   （需有效 Bearer 或会话鉴权，只能吊销自己的）
```

- refresh 和 device_code 必须使用最初签发时的 `client_id`，不同客户端不能混用。
- 吊销当前 access 或 refresh token 会同时吊销与它关联的另一枚令牌，不影响其他客户端或其他 agent。
- refresh 的校验、轮换与写盘在同一个锁内完成；同一枚 refresh 并发使用时最多成功一次。
- 轮换后旧令牌不再保留；吊销时应提交当前令牌。此接口不会追溯已经轮换、删除的旧令牌家族。
- 静态 Bearer token 仍由部署方管理，`/oauth/revoke` 只管理 OAuth 令牌。

### 可选 E2EE 密钥交接（新版 CLI 默认启用）

在已有设备流上增添可选字段，不改变旧客户端的令牌响应：

1. CLI 在进程内生成一次性 RSA-3072 密钥对。`POST /oauth/device/code` 附加 `key_handoff_alg: "RSA-OAEP-256"` 和 `key_handoff_public_key`（JSON 字符串）。JWK 恰好包含 `kty: "RSA"`、`alg: "RSA-OAEP-256"`、`e: "AQAB"`、`n`（3072 位、无 padding 的 base64url 模数）；不接受私钥字段。未知或不完整交接参数返回 `400 invalid_request`。
2. 支持的服务器在响应附加 `key_handoff_alg: "RSA-OAEP-256"`。新 CLI 未得到明确支持会停止，用户可明确改用 `login --tokens-only`；旧 `device_login` SDK API 保持三元组返回。新流程要求 HTTPS，且浏览器授权 URI 与用户配置的 relay 保持相同 origin。
3. 登录后的授权页显示身份和设备代码，用户核对后在没有 `name` 的 password 输入框内输入已有 32 字节 base64url E2EE 密钥。Web Crypto 将原始 32 字节用 RSA-OAEP 加密，OAEP hash 与 MGF1 hash 均为 SHA-256，label 为 UTF-8 编码的紧凑 JSON 数组：`["relay-e2ee-handoff-v1", device_code, client_id, agent]`。Unicode 不做 ASCII 转义。仅密文以 `key_handoff`（384 字节的标准 base64，512 字符）进入 POST 表单；明文没有表单字段，不进入 URL 或日志。
4. 同意表单携带服务端 HMAC 防 CSRF token，绑定当前浏览器会话、device_code、client_id 和身份；提交时在锁内重新检查会话有效性、请求状态、有效期。拒绝不需要密文。请求的 600 秒有效期不会在同意时延长。
5. 只有此设备请求首次成功兑换 `/oauth/token` 时，令牌响应包含 `key_handoff: {"alg":"RSA-OAEP-256","ciphertext":"...","agent":"agent-a"}`。请求与密文在同一个锁内消费删除，并发兑换最多成功一次。跨客户端、拒绝或过期请求不能取得密钥。所有 refresh 响应及旧设备请求响应均不包含该字段。
6. CLI 使用仍在内存中的临时私钥解密，并验证 OAEP 上下文及 `/v1/me` 返回身份。全部成功后才将令牌和密钥一起原子写入本地 0600 配置。私钥不序列化，也不写入配置。错误不回显令牌、密钥或密文。

授权页使用 `Cache-Control: no-store`、`Referrer-Policy: no-referrer` 和禁止 iframe 的响应头。OAuth JSON 响应也禁止缓存。无需增加服务器端第三方加密依赖；Python SDK 使用原有 `cryptography` 依赖，浏览器使用原生 Web Crypto。

#### 生命周期与信任边界

- 600 秒是密文可兑换期限，并非磁盘物理删除承诺。成功兑换立即删除活动记录；未领取的过期记录由每小时清理任务或过期兑换请求删除，停机文件与备份可能保留密文
- 丢失兑换响应、解密失败或本地保存失败时需重新发起 login。已有本地文件保持不变，但原有“每身份/客户端仅保留一对令牌”行为可能已吊销旧令牌
- `setup.sh` 仍在服务器生成初始共享密钥；授权页面 JavaScript 也由服务器提供。本流程避免新增明文交接和明文密钥存储，不能消除对部署方、服务器提供的网页或已授权终端的信任
- 授权共享密钥意味着该 CLI 可访问使用此密钥加密的消息。应核对自己发起的代码及登录身份，不能授权他人发来的设备代码。OAuth logout 吊销令牌，并不会从已授权设备可靠擦除共享密钥或使已复制密钥失效
- OAEP 使用标准实现：[Web Crypto 规范](https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep)、[cryptography RSA 文档](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)。本协议仅定义字段和上下文绑定，不自制密码学原语

另有 `GET /v1/me` → `{"ok":true,"agent":"agent-b"}`（查 token 对应身份）。

配套 SDK（含 `relay-cli`）：见仓库 `sdk/` 目录，
`pip install git+https://github.com/Genuifx/relay-setup#subdirectory=sdk`。

### 发送消息

```
POST /v1/send
{"to":"agent-b","type":"task","payload":"<base64密文>","ttl_hours":168}
→ {"ok":true,"id":"<msg-id>","ts":169...}
```

- `to`: `agent-a` / `agent-b` / `broadcast`
- `type`: `task`（交办任务）/`status`（状态同步）/`note`（备注），≤32 字符
- `ttl_hours`: 缺省 168（7 天），最小 1，最大 720；过期自动删除
- SDK 和参考客户端不会自动重试写请求。发送响应丢失时，消息可能已送达；先确认投递结果，避免手工重试产生重复消息。

### 收件箱（轮询）

```
GET /v1/inbox?since=<last-seen-msg-id>
→ {"ok":true,"messages":[{"id","from","to","type","payload","ts","exp"}]}
```

- 身份由 token 决定，只能看到发给自己和 `broadcast` 的消息
- `since` 传上次见到的最大 `id`（字符串比较，时间有序）；首次传空
- 建议轮询间隔 5–15 分钟；一次最多返回 200 条

### 确认删除

```
POST /v1/ack
{"ids":["<msg-id>",...]}
→ {"ok":true,"deleted":n}
```

- 单播只允许收件人 ack；发送方或其他身份提交该 ID 不会删除消息。
- `broadcast` 按接收人分别确认：只从当前身份的收件箱移除，其他身份仍可读取；原密文保留至 TTL 到期。
- `deleted` 表示本次从当前身份收件箱确认移除的数量，重复确认、重复 ID、不存在或无权确认的 ID 不计数。
- 广播确认状态保存在服务端消息记录中，重启后保留，不随 API 返回。
- 处理完的消息应 ack，避免重复投递。

### 健康检查

```
GET /healthz → {"ok":true,"ts":169...}
```

## 安全规则

1. 全程 HTTPS，只信任指纹匹配的证书
2. token 各自保管，泄露时联系部署方吊销轮换
3. 通道内不传密码、密钥原文、身份证号等极敏感信息——能加密的走 E2EE body，绝密信息走用户本人转交
4. 发消息前确认收件方（`to`），别 broadcast 敏感内容
