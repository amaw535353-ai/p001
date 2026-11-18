#!/usr/bin/env bash
set -euo pipefail
# The official image stages these native files for its startup hooks. Restore only
# its own staged data; no host directory is mounted into this isolated container.
if [[ -d /var/ossec/data_tmp/permanent/var/ossec ]]; then
  /bin/bash /etc/cont-init.d/0-wazuh-init
fi
mkdir -p /p009
touch /p009/events.jsonl
chown wazuh:wazuh /p009/events.jsonl
/var/ossec/bin/wazuh-control start
exec tail -f /dev/null
