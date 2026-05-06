#!/bin/bash
# Emergency rollback script for IPS Tuner
# Restores the most recent config backups and reloads Suricata

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== IPS TUNER EMERGENCY ROLLBACK ==="
echo

# Stop tuner
echo -e "[1] ${YELLOW}Stopping suricata-tuner...${NC}"
systemctl stop suricata-tuner 2>/dev/null && echo "    Stopped." || echo "    (Not running as service — OK)"

# Restore suppress.conf
echo -e "[2] ${YELLOW}Restoring config backups...${NC}"
LATEST_SUPPRESS=$(ls -t /etc/suricata/suppress.conf.backup.* 2>/dev/null | head -1)
if [ -n "$LATEST_SUPPRESS" ]; then
    cp "$LATEST_SUPPRESS" /etc/suricata/suppress.conf
    echo "    ✓ Restored suppress.conf from $LATEST_SUPPRESS"
else
    echo "    No suppress.conf backup found — skipping"
fi

# Restore threshold.conf
LATEST_THRESHOLD=$(ls -t /etc/suricata/threshold.conf.backup.* 2>/dev/null | head -1)
if [ -n "$LATEST_THRESHOLD" ]; then
    cp "$LATEST_THRESHOLD" /etc/suricata/threshold.conf
    echo "    ✓ Restored threshold.conf from $LATEST_THRESHOLD"
else
    echo "    No threshold.conf backup found — skipping"
fi

# Restore pass.rules
LATEST_PASS=$(ls -t /etc/suricata/rules/pass.rules.backup.* 2>/dev/null | head -1)
if [ -n "$LATEST_PASS" ]; then
    cp "$LATEST_PASS" /etc/suricata/rules/pass.rules
    echo "    ✓ Restored pass.rules from $LATEST_PASS"
else
    echo "    No pass.rules backup found — skipping"
fi

# Reload Suricata
echo -e "[3] ${YELLOW}Reloading Suricata rules...${NC}"
if suricatasc -c "reload-rules" 2>/dev/null; then
    echo "    ✓ Rules reloaded via suricatasc"
else
    echo "    suricatasc failed — restarting Suricata service..."
    systemctl restart suricata && echo "    ✓ Suricata restarted"
fi

echo
echo -e "${GREEN}✅ Rollback complete.${NC}"
echo "   Verify Suricata is healthy: systemctl status suricata"
