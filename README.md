# relay-setup

两个 AI agent 之间的异步消息中转站：自研极简 relay 服务 + 部署脚本 + 协议文档 + Python 参考客户端。

## 文件

- `relay.py` — 中转服务本体（Python 标准库，无第三方依赖）。提供 `/v1/send`、`/v1/inbox`、`/v1/ack`、` /healthz` 四个 JSON 接口，Bearer token 鉴权，消息 TTL 自动过期。
- `setup.sh` — 一键部署脚本（Debian）：装依赖、生成双 token、签自签证书、配 systemd、fail2ban、SSH 加固。生产环境请换成 Let's Encrypt 真证书。
- `PROTOCOL.md` — 完整协议说明：接口定义、端到端加密（AES-256-GCM）规范、安全规则。**接入方先读这个。**
- `client_example.py` — Python 参考客户端：Bearer 鉴权、收件箱轮询、ack、E2EE 加解密全实现。`pip install cryptography` 即可运行。

## 安全模型

- 消息正文用预共享密钥做 AES-256-GCM 加密后上传，消息接口只存密文。部署脚本仍在服务器生成初始密钥，且浏览器代码由服务器提供，因此仍需信任部署方和实际运行的网页；不能据此声称服务器失陷后必然无法解密。
- 两个 agent 各持独立 Bearer token，可单独吊销。
- 日志只记元数据，不记正文和 token。

## 凭证

部署时 `setup.sh` 会生成两套 token + 一把 E2E 密钥，保存在服务器 `/root/relay-credentials.txt`（仅 root 可读），由部署方通过可信渠道分别交给两个 agent。

## 浏览器授权与密钥交接

新版 `relay-cli login` 会在本地生成一次性 RSA 公钥/私钥。用户在浏览器中登录、核对设备代码、输入已有 E2EE 密钥并授权后，CLI 自动解密并将密钥和令牌一起保存到本地 0600 配置，不再需要终端 `set-key`。

浏览器用 Web Crypto 的 RSA-OAEP/SHA-256 加密密钥，服务端仅中转密文；私钥不离开 CLI 内存。需要 HTTPS 和支持 Web Crypto 的浏览器。旧服务器不支持时会明确报错；可升级服务器，或显式使用 `relay-cli login --tokens-only` 加原有 `relay-cli set-key`。详见 [SDK 文档](sdk/README.md) 和 [协议](PROTOCOL.md)。

### 升级已有部署

先升级服务器 `relay.py`，再升级 SDK。保留 `/etc/relay`、`/var/lib/relay` 和既有 TLS、令牌、密码、会话、E2EE 密钥；不要重新运行 `setup.sh`，它会重新生成凭据。部署时备份旧 `relay.py`，验证新文件语法后替换 `/opt/relay/relay.py`，重启 `relay.service` 并检查 `/healthz`。健康检查只证明服务在线，还需要实际浏览器授权和双方加密收发验收。

使用非默认 HTTPS 端口、IPv6 或反向代理的部署，应为服务设置准确的 `RELAY_PUBLIC_BASE`（例如 `https://relay.example:8443`），让 OAuth 授权链接保持与 CLI 配置相同的 origin。

## 本地回归测试

原有 30 项安全测试仅需 Python 标准库，无需安装 SDK 或运行部署脚本：

```bash
python3 -B -X pycache_prefix=/tmp/relay-test-pycache -m unittest discover -s tests -p test_security.py -v
```

测试只使用假凭据和自动清理的临时文件；通过内存模拟 socket 调用真实 HTTP handler，不监听端口、不连接真实中转站、不读取已有用户配置。`pycache_prefix` 避开仓库附带的历史字节码。

涵盖 OAuth 关联吊销与并发刷新、消息归属/广播独立 ack、配置创建权限及失败清理、发送响应丢失时防重复发送。


完整测试另需 SDK 已声明的 `cryptography` 依赖和 Node.js 22+（本次验证使用 Python 3.12、cryptography 50、Node.js 24）：

```bash
python3 -B -X pycache_prefix=/tmp/relay-test-pycache -m unittest discover -s tests -v
```

新测试通过同样的内存 HTTP handler、临时配置，以及 Node.js 的真实 Web Crypto 和模拟 DOM 验证交接；不监听端口、不读取生产秘密、不建立实际 OAuth 授权。覆盖浏览器与 Python 加解密互通、设备/身份绑定、CSRF、拒绝/过期、并发单次消费、refresh 不含密钥、错误响应不改配置、取消/重复提交及历史导航恢复。
