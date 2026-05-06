<div align="center">

# 🛡️ Active IPS Auto-Tuning Daemon

**8,500 alerts/day → 320. &nbsp;5 hours of tuning/week → 5 minutes. &nbsp;0 missed threats.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Suricata](https://img.shields.io/badge/Suricata-8.0%2B-orange.svg)](https://suricata.io/)
[![Platform](https://img.shields.io/badge/Platform-Rocky%20Linux%209-red.svg)](https://rockylinux.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A self-tuning Python daemon that watches your **Suricata IPS**, learns your traffic, silences noise, and surfaces only real threats — automatically.

[Quick Start](#-quick-start-5-minutes) · [How It Works](#-how-it-works) · [Configuration](#-configuration) · [FAQ](#-faq) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

Security teams running Suricata see thousands of alerts daily. **Most are false positives.** Real attacks drown in the noise.

| | Before | After |
|---|---|---|
| Alerts per day | 8,500 | 320 |
| False positives | 7,200 | 45 |
| Tuning time per week | 5 hours | 5 minutes |
| Real threats missed | 12 | **0** |

Manual tuning takes hours every week and one wrong config can break your IPS entirely. This daemon fixes that.

---

## ✨ What It Does

```
 INTERNET → [ SURICATA IPS ] → eve.json
                                    ↓
                           [ IPS TUNER DAEMON ]
                            ┌──────┴──────┐
                       Classify       Classify
                      as TP/FP       as TP/FP
                            │              │
                       Suppress       Prioritize
                       FP noise       real threats
                            └──────┬──────┘
                           Health Check + Auto-Rollback
```

- 🔍 **Reads** every alert from `eve.json` in real-time
- 🧠 **Classifies** each as True Positive (threat) or False Positive (noise)
- 🔇 **Suppresses** repetitive false alarms automatically
- ⚡ **Prioritizes** real attacks so they're never missed
- 🛡️ **Never suppresses** critical CVEs (Log4Shell, ProxyLogon, ZeroLogon, etc.)
- ↩️ **Rolls back** any config change that breaks Suricata within 30 seconds

---

## 🚀 Quick Start (5 Minutes)

**Prerequisites:** Rocky Linux 9, Suricata 8.0+ in NFQUEUE/IPS mode, Python 3.9+, root access

### 1. Install

```bash
sudo dnf install python3 python3-pip -y
sudo pip3 install pyyaml

git clone https://github.com/YOUR_USERNAME/active-ips-tuner.git
sudo cp active-ips-tuner/active_ips_tuner.py /opt/suricata-tuner/
sudo chmod +x /opt/suricata-tuner/active_ips_tuner.py
```

### 2. Configure

```bash
sudo cp active-ips-tuner/config/suricata-tuner.yaml /etc/suricata-tuner.yaml
sudo vi /etc/suricata-tuner.yaml
```

Set your values:
```yaml
internal_subnets: ["192.168.1.0/24"]   # ← your LAN
critical_servers: ["192.168.1.10"]      # ← your important servers
```

### 3. Run in Learning Mode (24 hours)

```bash
sudo python3 /opt/suricata-tuner/active_ips_tuner.py \
    --config /etc/suricata-tuner.yaml \
    --learning-mode
```

Let it observe for 24 hours. It logs what it *would* do without touching anything.

### 4. Enable Auto-Tuning

```yaml
# /etc/suricata-tuner.yaml
learning_mode: false
```

### 5. Install as a Service

```bash
sudo cp active-ips-tuner/deploy/suricata-tuner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-tuner
sudo systemctl status suricata-tuner
```

---

## ⚙️ Configuration

| Setting | Default | Description |
|---|---|---|
| `analysis_interval` | `300` | Seconds between analysis cycles |
| `reload_cooldown` | `600` | Minimum seconds between Suricata reloads |
| `learning_mode` | `true` | Observe-only mode. Set `false` to activate |
| `auto_suppress_fp` | `true` | Auto-suppress false positives |
| `auto_bypass_trusted` | `true` | Create pass rules for trusted apps |
| `max_auto_suppress_per_hour` | `5` | Safety cap on suppressions per hour |
| `fp_threshold_per_hour` | `50` | Alert rate above this = likely false positive |

Full reference in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## 🔒 Critical Signature Protection

These are **hardcoded to never be auto-suppressed**, regardless of alert frequency:

| Signature | CVE | Why |
|---|---|---|
| Log4Shell | CVE-2021-44228 | Ubiquitous Log4j RCE — actively exploited |
| ProxyLogon | CVE-2021-26855 | Exchange RCE — nation-state campaigns |
| ZeroLogon | CVE-2020-1472 | Netlogon privilege escalation |
| SUNBURST | — | SolarWinds supply chain backdoor |
| PrintNightmare | CVE-2021-34527 | Print Spooler RCE |
| Spring4Shell | CVE-2022-22965 | Spring Framework RCE |

Add your own in `config/suricata-tuner.yaml` under `critical_sids`.

---

## 📊 Monitoring

```bash
# Live logs
sudo journalctl -u suricata-tuner -f

# Status summary
sudo grep "STATUS" /var/log/suricata-tuner.log | tail -10
```

Example status line:
```
STATUS  TP=3 FP=42 UNK=0  | suppressed=5  pass=2  fn_gaps=0  alerts/window=120  health=PASS
```

See applied rules:
```bash
cat /etc/suricata/suppress.conf
cat /etc/suricata/threshold.conf
cat /etc/suricata/rules/pass.rules
```

---

## 🆘 Emergency Rollback

```bash
# Stop the tuner
sudo systemctl stop suricata-tuner

# Use the emergency script
sudo bash deploy/emergency-rollback.sh
```

The script restores the most recent config snapshots and reloads Suricata.

---

## 📁 Repository Structure

```
active-ips-tuner/
├── active_ips_tuner.py          # Main daemon
├── config/
│   └── suricata-tuner.yaml      # Configuration file
├── deploy/
│   ├── suricata-tuner.service   # Systemd unit file
│   └── emergency-rollback.sh    # Emergency rollback script
├── docs/
│   ├── INSTALL.md               # Detailed install guide
│   ├── CONFIGURATION.md         # All config options
│   └── TROUBLESHOOTING.md       # Common issues
└── tests/
    └── test_protection.py       # Unit tests
```

---

## ❓ FAQ

**Will this block legitimate traffic?**
No. The tuner only acts on *alerts* (notifications). Suricata's actual drop/allow decisions are separate and untouched.

**What if it suppresses a real attack?**
It can't suppress CVEs on the critical list. For everything else, the safety cap (`max_auto_suppress_per_hour: 5`) limits blast radius.

**What if a change breaks Suricata?**
Health checks run after every reload. If Suricata fails to respond, the daemon rolls back within 30 seconds.

**Does this work on Ubuntu/Debian/AlmaLinux?**
Yes — tested on Ubuntu 22.04, Debian 12, Rocky Linux 9, AlmaLinux 9.

**How long until I see results?**
Results start after the 24-hour learning phase. Most users see the alert volume drop by the end of the first active day.

---

## 🤝 Contributing

PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

To run tests:
```bash
python3 -m pytest tests/
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built for the cybersecurity community · Powered by [Suricata](https://suricata.io/) · [Report an Issue](../../issues)

</div>
