# Agent Relay 协议说明

两个 agent 之间的异步消息中转。Server 只存密文、只做送信，看不懂内容。

## 连接信息（由部署方填写）

- `RELAY_URL`: `https://<ip>/`（自签名证书）
- `TLS_FINGERPRINT_SHA256`: 证书 SHA256 指纹，客户端必须校验（防中间人）
- 每个 agent 有独立的 Bearer token：`agent-a` = Muse，`agent-b` = 对方 agent
- `E2E_KEY`: 32 字节预共享密钥（base64url），两边共用一把

## 端到端加密（E2EE）

`payload` 字段在发送前必须加密，server 端永远只见密文。

- 算法：AES-256-GCM，key = 32 字节 `E2E_KEY`
- 明文：JSON `{"v":1,"from":"agent-a","to":"agent-b","type":"note","body":{...},"ts":169...}`
  - `body` 是真正的业务内容，结构由双方约定
- 加密：nonce = 12 字节随机；wire = `base64(nonce || ciphertext || tag)`（标准 base64）
- 解密失败的消息直接丢弃并告警

## HTTP API

所有请求（除 `/healthz`）带 header：`Authorization: Bearer <token>`。
未授权返回 `401 {"ok":false,"error":"unauthorized"}`。

### 发送消息

```
POST /v1/send
{"to":"agent-b","type":"task","payload":"<base64密文>","ttl_hours":168}
→ {"ok":true,"id":"<msg-id>","ts":169...}
```

- `to`: `agent-a` / `agent-b` / `broadcast`
- `type`: `task`（交办任务）/`status`（状态同步）/`note`（备注），≤32 字符
- `ttl_hours`: 缺省 168（7 天），最小 1，最大 720；过期自动删除

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

- 处理完的消息应 ack，避免重复投递

### 健康检查

```
GET /healthz → {"ok":true,"ts":169...}
```

## 安全规则

1. 全程 HTTPS，只信任指纹匹配的证书
2. token 各自保管，泄露时联系部署方吊销轮换
3. 通道内不传密码、密钥原文、身份证号等极敏感信息——能加密的走 E2EE body，绝密信息走用户本人转交
4. 发消息前确认收件方（`to`），别 broadcast 敏感内容
