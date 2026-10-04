#!/usr/bin/env bash
# setup.sh -- deploy the agent relay on a fresh Debian Lightsail instance.
# Run as root. Idempotent-ish: safe to re-run (regenerates credentials).
set -euo pipefail

RELAY_PY_URL="${RELAY_PY_URL:?set RELAY_PY_URL to the raw URL of relay.py}"

echo "==> installing packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 openssl fail2ban curl ca-certificates > /dev/null
echo "==> enabling unattended security upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades 2>/dev/null || true

echo "==> hardening sshd (key-only)"
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
sshd -t && systemctl restart sshd
systemctl enable --now fail2ban

echo "==> laying out directories"
mkdir -p /etc/relay /var/lib/relay /opt/relay
chmod 700 /etc/relay

echo "==> generating credentials"
TOKEN_A=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
TOKEN_B=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
E2E_KEY=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
python3 - "$TOKEN_A" "$TOKEN_B" <<'PYEOF'
import hashlib, json, os, sys
ta, tb = sys.argv[1], sys.argv[2]
tokens = {
    hashlib.sha256(ta.encode()).hexdigest(): "agent-a",
    hashlib.sha256(tb.encode()).hexdigest(): "agent-b",
}
with open("/etc/relay/tokens.json", "w") as f:
    json.dump(tokens, f)
os.chmod("/etc/relay/tokens.json", 0o600)
PYEOF

echo "==> creating self-signed TLS certificate"
openssl req -x509 -newkey rsa:2048 -keyout /etc/relay/key.pem -out /etc/relay/cert.pem \
    -days 825 -nodes -subj "/CN=relay-sg" 2>/dev/null
chmod 600 /etc/relay/key.pem /etc/relay/cert.pem
FPRINT=$(openssl x509 -in /etc/relay/cert.pem -noout -sha256 -fingerprint | cut -d= -f2 | tr -d ':')

echo "==> installing relay.py"
curl -fsSL "$RELAY_PY_URL" -o /opt/relay/relay.py
chmod 755 /opt/relay/relay.py
python3 -m py_compile /opt/relay/relay.py && echo "    py_compile OK"

echo "==> installing systemd unit"
cat > /etc/systemd/system/relay.service <<'EOF'
[Unit]
Description=Agent message relay
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/relay/relay.py
Environment=RELAY_PORT=443
Restart=always
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now relay
sleep 3
systemctl is-active --quiet relay && echo "    relay service active"

echo "==> installing local healthcheck watchdog (restarts relay if wedged)"
curl -fsSL "${RELAY_PY_URL%relay.py}healthcheck.sh" -o /opt/relay/healthcheck.sh
chmod 755 /opt/relay/healthcheck.sh
cat > /etc/cron.d/relay-healthcheck <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root /opt/relay/healthcheck.sh
EOF
chmod 644 /etc/cron.d/relay-healthcheck
echo "    healthcheck cron installed"

PUBLIC_IP=$(curl -s --max-time 5 http://169.254.169.254/latest/meta-data/public-ipv4 || true)
[ -z "$PUBLIC_IP" ] && PUBLIC_IP="<fill-public-ip>"

echo "==> saving handoff credentials (root-only)"
cat > /root/relay-credentials.txt <<EOF
RELAY_URL=https://${PUBLIC_IP}/
TLS_FINGERPRINT_SHA256=${FPRINT}
AGENT_A_TOKEN=${TOKEN_A}
AGENT_B_TOKEN=${TOKEN_B}
E2E_KEY_BASE64URL=${E2E_KEY}
# agent-a = Muse (this assistant). agent-b = the other agent tool.
# Hand AGENT_B_TOKEN + E2E_KEY_BASE64URL + RELAY_URL + fingerprint to agent-b
# through the user's own trusted channel. Keep AGENT_A_TOKEN private to agent-a.
EOF
chmod 600 /root/relay-credentials.txt

echo "==> self-test"
curl -ks https://127.0.0.1/healthz; echo
SEND_OUT=$(curl -ks -H "Authorization: Bearer $TOKEN_A" -X POST https://127.0.0.1/v1/send \
    -d '{"to":"agent-b","type":"note","payload":"dGVzdA=="}')
echo "$SEND_OUT"
echo "$SEND_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok') and d.get('id'), d; print('    send OK')"
INBOX_OUT=$(curl -ks -H "Authorization: Bearer $TOKEN_B" "https://127.0.0.1/v1/inbox?since=")
echo "$INBOX_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok') and len(d['messages'])>=1, d; print('    inbox OK')"
UNAUTH=$(curl -ks -o /dev/null -w "%{http_code}" https://127.0.0.1/v1/inbox)
[ "$UNAUTH" = "401" ] && echo "    unauth correctly rejected (401)"

echo
echo "==============================================="
echo "DONE. TLS_FINGERPRINT_SHA256=${FPRINT}"
echo "Credentials saved to /root/relay-credentials.txt"
echo "==============================================="
