# Installation Guide

## Supported Platforms

| OS | Status |
|---|---|
| Rocky Linux 9 | ✅ Tested |
| AlmaLinux 9 | ✅ Tested |
| RHEL 9 | ✅ Tested |
| Ubuntu 22.04 | ✅ Tested |
| Debian 12 | ✅ Tested |
| CentOS Stream 9 | ✅ Tested |

## Requirements

- Suricata 8.0+ running in NFQUEUE/IPS inline mode
- Python 3.9+
- `suricatasc` binary available (included with Suricata)
- Root access
- `eve.json` logging enabled in Suricata config

## Step-by-Step Installation

### 1. Verify Suricata is in IPS mode

```bash
sudo suricata --build-info | grep NFQ
# Should output: NFQ support: yes
```

### 2. Verify eve.json is enabled

In `/etc/suricata/suricata.yaml`:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
```

Restart Suricata if you changed this:
```bash
sudo systemctl restart suricata
```

### 3. Install Python dependencies

**Rocky/RHEL/AlmaLinux:**
```bash
sudo dnf install python3 python3-pip -y
sudo pip3 install pyyaml
```

**Ubuntu/Debian:**
```bash
sudo apt install python3 python3-pip -y
sudo pip3 install pyyaml
```

### 4. Deploy the script

```bash
git clone https://github.com/YOUR_USERNAME/active-ips-tuner.git
sudo mkdir -p /opt/suricata-tuner
sudo cp active-ips-tuner/active_ips_tuner.py /opt/suricata-tuner/
sudo chmod +x /opt/suricata-tuner/active_ips_tuner.py
```

### 5. Install configuration

```bash
sudo cp active-ips-tuner/config/suricata-tuner.yaml /etc/suricata-tuner.yaml
```

Edit the config for your network:
```bash
sudo vi /etc/suricata-tuner.yaml
```

Minimum required changes:
```yaml
internal_subnets:
  - "192.168.1.0/24"    # ← your LAN subnet

critical_servers:
  - "192.168.1.10"      # ← your domain controller, etc.
```

### 6. Dry run to verify

```bash
sudo python3 /opt/suricata-tuner/active_ips_tuner.py \
    --config /etc/suricata-tuner.yaml \
    --dry-run \
    --verbose
```

You should see no errors. Press `Ctrl+C` to stop.

### 7. Run in learning mode (24 hours)

```bash
sudo python3 /opt/suricata-tuner/active_ips_tuner.py \
    --config /etc/suricata-tuner.yaml \
    --learning-mode
```

Leave this running for 24 hours. It observes and logs decisions without making changes.

### 8. Activate auto-tuning

Edit config:
```yaml
learning_mode: false
```

### 9. Install as systemd service

```bash
sudo cp active-ips-tuner/deploy/suricata-tuner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable suricata-tuner
sudo systemctl start suricata-tuner
```

Verify:
```bash
sudo systemctl status suricata-tuner
sudo journalctl -u suricata-tuner -f
```

## Uninstall

```bash
sudo systemctl stop suricata-tuner
sudo systemctl disable suricata-tuner
sudo rm /etc/systemd/system/suricata-tuner.service
sudo systemctl daemon-reload
sudo rm -rf /opt/suricata-tuner
sudo rm /etc/suricata-tuner.yaml
```

Suricata suppress/threshold/pass rule files created by the daemon are in `/etc/suricata/`. Review and remove manually if desired.
