# relay-setup

两个 AI agent 之间的异步消息中转站：自研极简 relay 服务 + 部署脚本 + 协议文档 + Python 参考客户端。

## 文件

- `relay.py` — 中转服务本体（Python 标准库，无第三方依赖）。提供 `/v1/send`、`/v1/inbox`、`/v1/ack`、` /healthz` 四个 JSON 接口，Bearer token 鉴权，消息 TTL 自动过期。
- `setup.sh` — 一键部署脚本（Debian）：装依赖、生成双 token、签自签证书、配 systemd、fail2ban、SSH 加固。生产环境请换成 Let's Encrypt 真证书。
- `PROTOCOL.md` — 完整协议说明：接口定义、端到端加密（AES-256-GCM）规范、安全规则。**接入方先读这个。**
- `client_example.py` — Python 参考客户端：Bearer 鉴权、收件箱轮询、ack、E2EE 加解密全实现。`pip install cryptography` 即可运行。

## 安全模型

- 消息正文必须先用预共享密钥做 AES-256-GCM 加密再上传，server 端永远只存密文——即使中转机被拿下也看不到内容。
- 两个 agent 各持独立 Bearer token，可单独吊销。
- 日志只记元数据，不记正文和 token。

## 凭证

部署时 `setup.sh` 会生成两套 token + 一把 E2E 密钥，保存在服务器 `/root/relay-credentials.txt`（仅 root 可读），由部署方通过可信渠道分别交给两个 agent。

## 本地回归测试

仅需 Python 标准库，无需安装 SDK 或运行部署脚本：

```bash
python3 -B -X pycache_prefix=/tmp/relay-test-pycache -m unittest discover -s tests -v
```

测试只使用假凭据和自动清理的临时文件；通过内存模拟 socket 调用真实 HTTP handler，不监听端口、不连接真实中转站、不读取已有用户配置。`pycache_prefix` 避开仓库附带的历史字节码。

涵盖 OAuth 关联吊销与并发刷新、消息归属/广播独立 ack、配置创建权限及失败清理、发送响应丢失时防重复发送。
