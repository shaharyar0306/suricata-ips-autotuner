# Troubleshooting

## Daemon won't start

**Check logs first:**
```bash
sudo journalctl -u suricata-tuner -n 50 --no-pager
```

**Common causes:**

`FileNotFoundError: eve.json` — Suricata isn't writing eve.json. Verify `eve-log` is enabled in `/etc/suricata/suricata.yaml` and Suricata is running.

`suricatasc: command not found` — Set the correct path in config: `suricatasc_path: /usr/bin/suricatasc`

`PermissionError` — Run as root or check file permissions on `/etc/suricata/`.

---

## Health check fails after reload

The daemon rolls back automatically. Check what changed:
```bash
sudo grep "ROLLBACK" /var/log/suricata-tuner.log
```

If Suricata keeps failing to reload, there may be a syntax error in an existing config file. Check:
```bash
sudo suricata --dry-run -c /etc/suricata/suricata.yaml
```

---

## Too many suppressions happening

Lower the cap:
```yaml
max_auto_suppress_per_hour: 2
```

Or raise the threshold so fewer rules qualify as false positives:
```yaml
fp_threshold_per_hour: 100
```

---

## A rule I care about got suppressed

1. Add its SID to `critical_sids` in config — it will never be suppressed again
2. Restore it: `sudo grep "SUPPRESS" /var/log/suricata-tuner.log` to find the SID, then remove the corresponding entry from `/etc/suricata/suppress.conf`
3. Reload: `sudo suricatasc -c "reload-rules"`

---

## Eve.json is growing too fast

This is a Suricata config issue, not the tuner. In `/etc/suricata/suricata.yaml`, reduce logging verbosity or enable log rotation.

---

## Suricata reloads too frequently

Increase the cooldown:
```yaml
reload_cooldown: 1800   # 30 minutes minimum between reloads
```

---

## Need to fully reset tuner state

```bash
sudo systemctl stop suricata-tuner
sudo bash deploy/emergency-rollback.sh
# Then clear the log
sudo truncate -s 0 /var/log/suricata-tuner.log
sudo systemctl start suricata-tuner
```
