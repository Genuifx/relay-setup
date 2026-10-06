#!/usr/bin/env python3
"""relay-cli -- command line interface for the agent message relay.

Usage:
  relay-cli [--server URL] login [--tokens-only]  browser approval + key handoff
  relay-cli set-key                     save the E2EE key (typed by a human)
  relay-cli whoami
  relay-cli send --to agent-a --body "hi" [--type note]
  relay-cli inbox [--decrypt] [--ack] [--limit 20]
  relay-cli ack --ids <id1,id2>
  relay-cli logout

Config: ~/.config/relay-cli/config.json (0600), or $RELAY_CLI_CONFIG.
"""
import argparse
import datetime
import getpass
import http.client
import json
import os
import sys
import time

from .auth import TokenStore, device_login, device_login_with_key, get_valid_token, DEFAULT_CLIENT_ID
from .client import RelayClient, RelayError
from .crypto import e2e_encrypt, e2e_decrypt

DEFAULT_SERVER = "https://g-relay.duckdns.org"


def die(msg, code=1):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


def make_client(args, store):
    server = args.server or store.server or DEFAULT_SERVER
    try:
        token = get_valid_token(store, server, args.client_id)
    except RuntimeError as e:
        die(str(e))
    return RelayClient(server, token), store


def get_e2e_key(args, store, required=True):
    key = args.e2e_key or os.environ.get("RELAY_E2E_KEY") or store.data.get("e2e_key")
    if not key and required:
        die("no E2EE key: use --e2e-key, $RELAY_E2E_KEY, or `relay-cli set-key`")
    return key


def cmd_login(args):
    store = TokenStore(args.config)
    server = args.server or store.server or DEFAULT_SERVER
    key = None
    try:
        if args.tokens_only:
            access, refresh, expires_in = device_login(server, args.client_id)
            agent = RelayClient(server, access).me()
        else:
            access, refresh, expires_in, key, agent = device_login_with_key(server, args.client_id)
    except (RuntimeError, OSError, http.client.HTTPException) as e:
        die(str(e))
    # No config mutation until decryption AND token identity verification succeed.
    if args.tokens_only and (store.server != server or store.agent != agent):
        store.data.pop("e2e_key", None)  # Never carry an unrelated server's key.
    store.data.update({
        "server": server, "agent": agent, "access_token": access,
        "refresh_token": refresh, "access_expires_at": time.time() + expires_in,
    })
    if key is not None:
        store.data["e2e_key"] = key
    try:
        store.save()
    except OSError:
        die("配置保存失败；请重新 login。原配置文件未替换，旧令牌可能已被服务端轮换。")
    print("已登录为 %s，令牌%s已保存。" % (agent, "和 E2EE 密钥" if key else ""))
    if args.tokens_only:
        print("仅更新令牌；E2EE 密钥未交接。如有需要，请运行 relay-cli set-key。")


def cmd_set_key(args):
    store = TokenStore(args.config)
    if args.key:
        key = args.key
    else:
        key = getpass.getpass("粘贴 E2EE 密钥（输入不可见）：").strip()
    if not key:
        die("empty key")
    from .crypto import load_key
    try:
        load_key(key)
    except ValueError as e:
        die(str(e))
    store.data["e2e_key"] = key
    store.save()
    print("E2EE 密钥已保存到本地配置（仅本机可读）。")


def cmd_whoami(args):
    store = TokenStore(args.config)
    client, _ = make_client(args, store)
    print(client.me())


def read_body(args):
    if args.body is not None:
        return args.body
    if args.body_file:
        with open(args.body_file) as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    die("no body: use --body, --body-file, or pipe via stdin")


def cmd_send(args):
    store = TokenStore(args.config)
    client, _ = make_client(args, store)
    key = get_e2e_key(args, store)
    body = read_body(args)
    agent = store.agent or client.me()
    payload = e2e_encrypt(key, agent, args.to, args.type, body)
    d = client.send(args.to, args.type, payload, ttl_hours=args.ttl)
    print(json.dumps({"ok": True, "id": d["id"]}, ensure_ascii=False))


def cmd_inbox(args):
    store = TokenStore(args.config)
    client, _ = make_client(args, store)
    key = get_e2e_key(args, store, required=False)
    msgs = client.inbox(args.since)
    if args.limit and len(msgs) > args.limit:
        msgs = msgs[-args.limit:]
    out = []
    for m in msgs:
        item = {"id": m["id"], "from": m["from"], "type": m.get("type"),
                "ts": m["ts"],
                "time": datetime.datetime.fromtimestamp(
                    m["ts"], datetime.timezone.utc).astimezone().strftime(
                        "%Y-%m-%d %H:%M:%S")}
        if args.decrypt is not False and key:
            try:
                item["body"] = e2e_decrypt(key, m["payload"])["body"]
            except Exception as e:
                item["body"] = "<decrypt failed: %s>" % e
                item["payload_len"] = len(m["payload"])
        else:
            item["payload_len"] = len(m["payload"])
        out.append(item)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if args.ack and out:
        n = client.ack([m["id"] for m in out])
        print("acked %d message(s)" % n, file=sys.stderr)


def cmd_ack(args):
    store = TokenStore(args.config)
    client, _ = make_client(args, store)
    ids = [i.strip() for i in args.ids.split(",") if i.strip()]
    if not ids:
        die("no ids")
    print("deleted %d" % client.ack(ids))


def cmd_logout(args):
    store = TokenStore(args.config)
    server = args.server or store.server
    token = store.data.get("access_token")
    revoke_error = None
    if server and (token or store.data.get("refresh_token")):
        try:
            if store.data.get("refresh_token"):
                # Revocation still requires valid authentication. If access
                # expired, rotate once and revoke the newly current pair.
                token = get_valid_token(store, server, args.client_id)
            RelayClient(server, token).revoke_token(token)
            print("服务端令牌已吊销。")
        except (RelayError, RuntimeError, OSError, http.client.HTTPException) as e:
            revoke_error = str(e)
    elif token or store.data.get("refresh_token"):
        revoke_error = "no server configured"
    store.clear_tokens()
    print("本地令牌已清除。")
    if revoke_error:
        raise RelayError("local tokens cleared; server revocation was not confirmed: "
                         + revoke_error)


def build_parser():
    p = argparse.ArgumentParser(prog="relay-cli", description="agent message relay CLI")
    p.add_argument("--server", default=None, help="relay base URL")
    p.add_argument("--config", default=None, help="config file path")
    p.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    p.add_argument("--e2e-key", default=None, help="E2EE key (or $RELAY_E2E_KEY)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("login", help="OAuth login with browser E2EE key handoff")
    s.add_argument("--tokens-only", action="store_true",
                   help="legacy token-only login; configure the E2EE key separately")
    s.set_defaults(func=cmd_login)

    s = sub.add_parser("set-key", help="save the E2EE key locally")
    s.add_argument("--key", default=None)
    s.set_defaults(func=cmd_set_key)

    s = sub.add_parser("whoami", help="show logged-in agent id")
    s.set_defaults(func=cmd_whoami)

    s = sub.add_parser("send", help="encrypt and send a message")
    s.add_argument("--to", required=True, help="agent-a | agent-b | broadcast")
    s.add_argument("--type", default="note")
    s.add_argument("--body", default=None)
    s.add_argument("--body-file", default=None)
    s.add_argument("--ttl", type=int, default=168, help="ttl hours")
    s.set_defaults(func=cmd_send)

    s = sub.add_parser("inbox", help="list inbox messages")
    s.add_argument("--since", default="")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--no-decrypt", dest="decrypt", action="store_false")
    s.add_argument("--ack", action="store_true", help="ack listed messages")
    s.set_defaults(func=cmd_inbox)

    s = sub.add_parser("ack", help="ack (delete) messages by id")
    s.add_argument("--ids", required=True, help="comma-separated ids")
    s.set_defaults(func=cmd_ack)

    s = sub.add_parser("logout", help="revoke token and clear local config")
    s.set_defaults(func=cmd_logout)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except RelayError as e:
        die(str(e))
    except KeyboardInterrupt:
        die("interrupted", code=130)


if __name__ == "__main__":
    main()
