# Configuration Reference

The config file lives at `/etc/suricata-tuner.yaml`.

## Full Example

```yaml
# Paths
eve_log_path: /var/log/suricata/eve.json
suppress_conf: /etc/suricata/suppress.conf
threshold_conf: /etc/suricata/threshold.conf
pass_rules: /etc/suricata/rules/pass.rules
suricatasc_path: /usr/bin/suricatasc
backup_dir: /etc/suricata/tuner-backups/

# Tuning behavior
learning_mode: false
auto_suppress_fp: true
auto_bypass_trusted: true
analysis_interval: 300
reload_cooldown: 600
max_auto_suppress_per_hour: 5
fp_threshold_per_hour: 50

# Your network
internal_subnets:
  - "192.168.1.0/24"
  - "10.0.0.0/8"

critical_servers:
  - "192.168.1.10"
  - "192.168.1.11"

# SIDs that will NEVER be auto-suppressed
critical_sids:
  - 2034131   # Log4Shell
  - 2031412   # ProxyLogon
  - 2031900   # ZeroLogon
  - 2031449   # SUNBURST
  - 2033462   # PrintNightmare
  - 2036000   # Spring4Shell
```

## Option Reference

### Paths

| Option | Default | Description |
|---|---|---|
| `eve_log_path` | `/var/log/suricata/eve.json` | Suricata eve.json log file |
| `suppress_conf` | `/etc/suricata/suppress.conf` | Suppression rules file |
| `threshold_conf` | `/etc/suricata/threshold.conf` | Threshold rules file |
| `pass_rules` | `/etc/suricata/rules/pass.rules` | Pass rules file |
| `suricatasc_path` | `/usr/bin/suricatasc` | Path to suricatasc binary |
| `backup_dir` | `/etc/suricata/tuner-backups/` | Where config snapshots are stored |

### Behavior

| Option | Default | Description |
|---|---|---|
| `learning_mode` | `true` | Log decisions without applying changes. Set `false` to activate. |
| `auto_suppress_fp` | `true` | Automatically add suppress rules for classified false positives |
| `auto_bypass_trusted` | `true` | Create pass rules for trusted internal traffic patterns |
| `analysis_interval` | `300` | Seconds between analysis cycles (5 minutes) |
| `reload_cooldown` | `600` | Minimum seconds between Suricata rule reloads (10 minutes) |
| `max_auto_suppress_per_hour` | `5` | Hard cap on automatic suppressions per hour |
| `fp_threshold_per_hour` | `50` | Alert rate (per hour) above which a rule is classified as likely FP |

### Network

| Option | Description |
|---|---|
| `internal_subnets` | List of your internal CIDR ranges. Used to distinguish inside vs outside traffic. |
| `critical_servers` | IPs of high-value servers (DCs, DB servers, etc.). Alerts involving these are never suppressed. |

### Critical SIDs

`critical_sids` is a list of Suricata SIDs that will **never** be automatically suppressed, regardless of alert frequency. Add any SID you consider critical for your environment.

To find a rule's SID:
```bash
grep "rule_name_keyword" /etc/suricata/rules/*.rules | grep -o 'sid:[0-9]*'
```
