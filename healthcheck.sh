#!/bin/bash
# healthcheck.sh -- local watchdog for the relay service.
# Runs from cron every 5 minutes; restarts the service if it stops answering.
# (The service wedged twice in 12h in Oct 2026: process alive but no longer
# accept()ing connections. Root cause undetermined; SYN flood warnings were
# seen on 443. This makes recovery automatic.)
set -u
if curl -k -s -m 10 -o /dev/null "https://127.0.0.1/healthz"; then
  exit 0
fi
logger -t relay-healthcheck "healthz failed, restarting relay service"
systemctl restart relay
