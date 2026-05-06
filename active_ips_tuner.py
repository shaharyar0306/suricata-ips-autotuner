#!/usr/bin/env python3
"""
ACTIVE INLINE IPS TUNING DAEMON for Suricata
============================================
Watches eve.json in real-time, classifies events into TP/FP/TN/FN,
and actively updates Suricata's running configuration.

Includes:
  - Critical Signature Protection (never-suppress guard)
  - Health Check + Automatic Rollback
  - Apply-with-Safety Wrapper (snapshot, dedup, rollback)

Designed for INLINE deployment — traffic flows THROUGH Suricata.

Usage:
    sudo python3 active_ips_tuner.py [--config /path/to/config.yaml] [--dry-run]

Author: IPS Tuning Framework
License: MIT
"""

import argparse
import ipaddress
import json
import logging
import logging.handlers
import os
import pickle
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

DEFAULT_CONFIG: Dict[str, Any] = {
    # ---- File paths ----
    "paths": {
        "eve_log": "/var/log/suricata/eve.json",
        "threshold_file": "/etc/suricata/threshold.conf",
        "suppress_file": "/etc/suricata/suppress.conf",
        "pass_rules_file": "/etc/suricata/rules/pass.rules",
        "custom_rules_file": "/etc/suricata/rules/custom-tp.rules",
        "rules_dir": "/var/lib/suricata/rules",
        "pid_file": "/var/run/suricata.pid",
        "state_file": "/var/lib/suricata-tuner/state.pkl",
        "log_file": "/var/log/suricata-tuner.log",
        "suricatasc": "suricatasc",
    },

    # ---- Tuning intervals (seconds) ----
    "intervals": {
        "analysis_interval": 300,        # 5 min
        "reload_cooldown": 900,          # 10 min
        "learning_mode_duration": 86400, # 24 h
        "state_save_interval": 600,      # 10 min
        "stats_window_seconds": 3600,    # 1 h sliding window
    },

    # ---- Classification thresholds ----
    "thresholds": {
        "fp_threshold_per_hour": 50,
        "tp_confidence_threshold": 0.6,
        "fp_confidence_threshold": 0.7,
        "fp_score_threshold": 5,
        "fn_detection_threshold": 3,
        "fp_storm_threshold": 1000,
    },

    # ---- Network definitions ----
    "network": {
        "internal_subnets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                             "fc00::/7", "fe80::/10"],
        "critical_servers": ["10.0.1.10", "10.0.1.20", "10.0.2.5"],
        "trusted_scanners": ["10.0.0.100"],
        "threat_intel_feeds": [],  # IPs known malicious
        "trusted_applications": {},
    },

    # ---- Auto-action policies ----
    "actions": {
        "auto_suppress_fp": True,
        "auto_enable_tp_rules": False,
        "auto_bypass_trusted": True,
        "max_auto_suppress_per_hour": 5,
        "max_auto_pass_per_hour": 3,
        "dry_run": False,
        "learning_mode": False,  # If True, classify but never write changes
    },

    # ---- Performance protection ----
    "performance": {
        "max_rules_total": 50000,
        "cpu_bypass_threshold": 85,
        "max_config_file_size": 10_000_000,  # 10 MB
        "max_history_events": 50_000,
    },

    # ---- Notifications ----
    "notifications": {
        "alert_on_fn_detected": True,
        "alert_on_major_fp_storm": True,
        "syslog_enabled": False,
        "syslog_address": "/dev/log",
    },

    # ---- Critical Signature Protection ----
    "protection": {
        "never_suppress_sids": [
            2100378,   # ET EXPLOIT Log4Shell (Log4j RCE, CVE-2021-44228)
            2035247,   # ET EXPLOIT ProxyLogon (Exchange, CVE-2021-26855)
            2024502,   # ET EXPLOIT Zerologon (CVE-2020-1472)
            2031365,   # ET EXPLOIT SolarWinds SUNBURST
            2034647,   # ET EXPLOIT PrintNightmare (CVE-2021-34527)
            2027390,   # ET TROJAN Cobalt Strike beacon
            2029309,   # ET EXPLOIT Spring4Shell (CVE-2022-22965)
        ],
        "never_suppress_sid_ranges": [
            [2100000, 2100999],   # ET high-confidence exploit kit hits
        ],
        "never_suppress_classtypes": [
            "trojan-activity",
            "shellcode-detect",
            "successful-admin",
            "successful-user",
            "attempted-admin",
            "web-application-attack",
        ],
        "never_suppress_metadata_tags": [
            "cve",
            "mitre_attack_t1190",
            "mitre_attack_t1059",
            "ransomware",
            "apt",
        ],
        "never_suppress_msg_patterns": [
            r"(?i)log4shell",
            r"(?i)proxylogon",
            r"(?i)zerologon",
            r"(?i)ransomware",
            r"(?i)cobalt\s*strike",
            r"(?i)\bRCE\b",
            r"(?i)reverse\s*shell",
        ],
        "min_severity_to_suppress": 3,
        "protection_list_file": None,
    },

    # ---- Health Check & Rollback ----
    "health": {
        "enabled": True,
        "post_reload_settle_seconds": 5,
        "post_reload_observation_seconds": 30,
        "drop_spike_multiplier": 3.0,
        "min_alerts_after_reload": 0,
        "backup_retention": 10,
        "rollback_on_failure": True,
        "stats_endpoint_check": True,
    },
}


# ============================================================
# DATA STRUCTURES
# ============================================================

class Classification(str, Enum):
    UNKNOWN = "UNKNOWN"
    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    TRUE_NEGATIVE = "TN"
    FALSE_NEGATIVE = "FN"


@dataclass
class SignatureStats:
    """Tracks per-signature statistics over a sliding window."""
    sig_id: int
    msg: str = ""
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)
    recent_timestamps: deque = field(default_factory=lambda: deque(maxlen=10_000))
    classification: Classification = Classification.UNKNOWN
    confidence: float = 0.0
    action_taken: Optional[str] = None
    last_classified: Optional[datetime] = None

    def rate_per_hour(self, window_seconds: int = 3600) -> float:
        """Compute event rate over the last N seconds."""
        if not self.recent_timestamps:
            return 0.0
        cutoff = datetime.now() - timedelta(seconds=window_seconds)
        recent = [t for t in self.recent_timestamps if t >= cutoff]
        if not recent:
            return 0.0
        elapsed = (datetime.now() - recent[0]).total_seconds()
        if elapsed <= 0:
            return float(len(recent))
        return len(recent) * 3600.0 / max(elapsed, 1.0)


@dataclass
class TuningAction:
    type: str           # SUPPRESS | PRIORITIZE | CREATE_PASS | FN_ALERT
    sig_id: Optional[int] = None
    rule: Optional[str] = None
    reason: str = ""
    severity: str = "INFO"
    detail: str = ""
    fix: str = ""
    app: str = ""


# ============================================================
# CONFIG LOADER
# ============================================================

def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load YAML config and deep-merge with defaults."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if not config_path:
        return cfg
    if not HAS_YAML:
        print("[WARN] PyYAML not installed; ignoring --config", file=sys.stderr)
        return cfg
    try:
        with open(config_path, "r") as f:
            user = yaml.safe_load(f) or {}
        _deep_merge(cfg, user)
        print(f"[*] Loaded config from {config_path}")
    except Exception as e:
        print(f"[ERROR] Failed to load config {config_path}: {e}", file=sys.stderr)
    return cfg


def _deep_merge(base: dict, overlay: dict) -> None:
    for k, v in overlay.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ============================================================
# LOGGING SETUP
# ============================================================

def setup_logging(cfg: Dict[str, Any], verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("ips-tuner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    # Console
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # File
    log_path = cfg["paths"].get("log_file")
    if log_path:
        try:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=10_000_000, backupCount=5
            )
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except Exception as e:
            print(f"[WARN] Cannot open log file {log_path}: {e}", file=sys.stderr)

    # Syslog
    if cfg["notifications"].get("syslog_enabled"):
        try:
            sysh = logging.handlers.SysLogHandler(
                address=cfg["notifications"].get("syslog_address", "/dev/log")
            )
            sysh.setFormatter(logging.Formatter("ips-tuner: %(message)s"))
            logger.addHandler(sysh)
        except Exception as e:
            print(f"[WARN] Syslog init failed: {e}", file=sys.stderr)

    return logger


# ============================================================
# NETWORK HELPERS (cached)
# ============================================================

class NetworkMatcher:
    """Caches subnet objects and provides fast IP membership checks."""

    def __init__(self, net_cfg: Dict[str, Any]):
        self.internal_nets = self._compile(net_cfg.get("internal_subnets", []))
        self.critical_servers = set(net_cfg.get("critical_servers", []))
        self.trusted_scanners = set(net_cfg.get("trusted_scanners", []))
        self.threat_intel = set(net_cfg.get("threat_intel_feeds", []))

        # Pre-compile trusted apps
        self.trusted_apps: List[Tuple[str, List, set]] = []
        for app, conf in net_cfg.get("trusted_applications", {}).items():
            nets = self._compile(conf.get("ips", []))
            ports = set(conf.get("ports", []))
            self.trusted_apps.append((app, nets, ports))

    @staticmethod
    def _compile(items: List[str]):
        nets = []
        for x in items:
            try:
                if "/" in x:
                    nets.append(ipaddress.ip_network(x, strict=False))
                else:
                    addr = ipaddress.ip_address(x)
                    nets.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"))
            except ValueError:
                pass
        return nets

    @staticmethod
    def _to_ip(ip: str):
        try:
            return ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return None

    def is_internal(self, ip: str) -> bool:
        addr = self._to_ip(ip)
        if not addr:
            return False
        return any(addr in n for n in self.internal_nets)

    def is_critical(self, ip: str) -> bool:
        return ip in self.critical_servers

    def is_trusted_scanner(self, ip: str) -> bool:
        return ip in self.trusted_scanners

    def is_threat_intel(self, ip: str) -> bool:
        return ip in self.threat_intel

    def matching_trusted_app(self, ip: str, port: int) -> Optional[str]:
        addr = self._to_ip(ip)
        if not addr:
            return None
        for app, nets, ports in self.trusted_apps:
            if any(addr in n for n in nets) and (not ports or port in ports):
                return app
        return None


# ============================================================
# SURICATA CONTROL
# ============================================================

class SuricataController:
    """Wraps suricatasc invocations with timeout and dry-run support."""

    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.bin = cfg["paths"].get("suricatasc", "suricatasc")
        self.dry_run = cfg["actions"].get("dry_run", False)

    def _run(self, cmd: List[str], timeout: int = 30) -> Optional[str]:
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if res.returncode != 0:
                self.logger.warning("suricatasc failed: %s", res.stderr.strip())
                return None
            return res.stdout
        except FileNotFoundError:
            self.logger.error("suricatasc binary not found: %s", self.bin)
        except subprocess.TimeoutExpired:
            self.logger.warning("suricatasc timeout: %s", " ".join(cmd))
        except Exception as e:
            self.logger.error("suricatasc error: %s", e)
        return None

    def reload_rules(self) -> bool:
        if self.dry_run:
            self.logger.info("[DRY-RUN] Would reload Suricata rules")
            return True
        out = self._run([self.bin, "-c", "reload-rules"])
        if out is not None:
            self.logger.info("Suricata rules reloaded successfully")
            return True
        return False

    def get_packet_drops(self) -> int:
        out = self._run([self.bin, "-c", "dump-counters"], timeout=5)
        if not out:
            return 0
        try:
            data = json.loads(out)
            drops = 0
            def find(d):
                nonlocal drops
                if isinstance(d, dict):
                    for k, v in d.items():
                        if k.endswith("kernel_drops") and isinstance(v, int):
                            drops += v
                        else:
                            find(v)
                elif isinstance(d, list):
                    for x in d:
                        find(x)
            find(data)
            return drops
        except json.JSONDecodeError:
            m = re.search(r"kernel_drops[^\d]*(\d+)", out)
            return int(m.group(1)) if m else 0


# ============================================================
# RULE GENERATORS
# ============================================================

class RuleGenerator:
    """Generates suppress, threshold, and pass rules safely."""

    @staticmethod
    def suppress(sig_id: int, src_ip: Optional[str] = None,
                 dst_ip: Optional[str] = None) -> str:
        rule = f"suppress gen_id 1, sig_id {sig_id}"
        if src_ip:
            rule += f", track by_src, ip {src_ip}"
        elif dst_ip:
            rule += f", track by_dst, ip {dst_ip}"
        return f"{rule}  # auto-tuner {datetime.now().isoformat(timespec='seconds')}"

    @staticmethod
    def threshold(sig_id: int, ttype: str, count: int, seconds: int,
                  track: str = "by_src") -> str:
        return (f"threshold gen_id 1, sig_id {sig_id}, type {ttype}, "
                f"track {track}, count {count}, seconds {seconds}  "
                f"# auto-tuner {datetime.now().isoformat(timespec='seconds')}")

    @staticmethod
    def pass_rule(ip: str, port: int, app_name: str) -> str:
        sid = 9_000_000 + (abs(hash(f"{app_name}:{ip}:{port}")) % 100_000)
        safe_app = re.sub(r"[^A-Za-z0-9_\-]", "_", app_name)
        return (f'pass ip {ip} any -> any {port} '
                f'(msg:"AUTO-TN bypass for {safe_app}"; '
                f'sid:{sid}; rev:1; classtype:not-suspicious;)')


# ============================================================
# MODULE 1: CRITICAL SIGNATURE PROTECTION
# ============================================================

class CriticalSigProtection:
    """
    Hard guard against suppressing high-impact detections.
    Loaded from config + optional external file. All checks are
    fail-closed: any error or doubt => cannot suppress.
    """

    _rule_meta_cache: Dict[int, Dict[str, Any]] = {}
    _meta_loaded: bool = False

    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.logger = logger
        prot = cfg.get("protection", {})

        self.never_sids: set = set(prot.get("never_suppress_sids", []))
        self.never_ranges: List[Tuple[int, int]] = [
            tuple(r) for r in prot.get("never_suppress_sid_ranges", [])
            if isinstance(r, (list, tuple)) and len(r) == 2
        ]
        self.never_classtypes: set = {
            c.lower() for c in prot.get("never_suppress_classtypes", [])
        }
        self.never_meta_tags: set = {
            t.lower() for t in prot.get("never_suppress_metadata_tags", [])
        }
        self.msg_patterns: List[re.Pattern] = []
        for p in prot.get("never_suppress_msg_patterns", []):
            try:
                self.msg_patterns.append(re.compile(p))
            except re.error as e:
                self.logger.warning("Bad msg pattern %r: %s", p, e)

        self.min_severity = int(prot.get("min_severity_to_suppress", 3))

        # Optional external SID list
        ext = prot.get("protection_list_file")
        if ext and os.path.exists(ext):
            try:
                with open(ext, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            self.never_sids.add(int(line.split()[0]))
                        except ValueError:
                            continue
                self.logger.info("Loaded %d additional protected SIDs from %s",
                                 len(self.never_sids), ext)
            except Exception as e:
                self.logger.warning("Failed to read %s: %s", ext, e)

        self.logger.info(
            "Protection loaded: %d SIDs, %d ranges, %d classtypes, "
            "%d tags, %d patterns, min_severity=%d",
            len(self.never_sids), len(self.never_ranges),
            len(self.never_classtypes), len(self.never_meta_tags),
            len(self.msg_patterns), self.min_severity)

    def can_suppress(self, sig_id: int,
                     stats: "SignatureStats") -> Tuple[bool, str]:
        """Return (allowed, reason_if_blocked)."""
        # 1. Direct SID match
        if sig_id in self.never_sids:
            return False, f"PROTECTED_SID({sig_id})"

        # 2. SID range
        for lo, hi in self.never_ranges:
            if lo <= sig_id <= hi:
                return False, f"PROTECTED_SID_RANGE({lo}-{hi})"

        # 3. Severity guard (Suricata: lower = more severe)
        if stats.severities:
            most_common_sev = stats.severities.most_common(1)[0][0]
            try:
                if int(most_common_sev) < self.min_severity:
                    return False, f"HIGH_SEVERITY({most_common_sev})"
            except (TypeError, ValueError):
                pass

        # 4. Message pattern match
        msg = (stats.msg or "")
        for pat in self.msg_patterns:
            if pat.search(msg):
                return False, f"PROTECTED_MSG_PATTERN({pat.pattern})"

        # 5. Classtype / metadata enrichment from rule files (best-effort)
        meta = self._lookup_rule_metadata(sig_id)
        if meta:
            ct = (meta.get("classtype") or "").lower()
            if ct in self.never_classtypes:
                return False, f"PROTECTED_CLASSTYPE({ct})"
            tags = {t.lower() for t in meta.get("metadata_tags", [])}
            hit = tags & self.never_meta_tags
            if hit:
                return False, f"PROTECTED_METADATA({','.join(sorted(hit))})"

        return True, ""

    def _lookup_rule_metadata(self, sig_id: int) -> Optional[Dict[str, Any]]:
        if not self._meta_loaded:
            self._load_rule_metadata()
        return self._rule_meta_cache.get(sig_id)

    def _load_rule_metadata(self) -> None:
        self._meta_loaded = True
        rules_dir = "/var/lib/suricata/rules"
        if not os.path.isdir(rules_dir):
            return
        sid_re = re.compile(r"\bsid\s*:\s*(\d+)")
        ct_re = re.compile(r"\bclasstype\s*:\s*([\w\-]+)")
        meta_re = re.compile(r"\bmetadata\s*:\s*([^;]+);")
        try:
            for root, _, files in os.walk(rules_dir):
                for fname in files:
                    if not fname.endswith(".rules"):
                        continue
                    try:
                        with open(os.path.join(root, fname),
                                  "r", errors="ignore") as f:
                            for line in f:
                                if "sid:" not in line:
                                    continue
                                m = sid_re.search(line)
                                if not m:
                                    continue
                                sid = int(m.group(1))
                                ct = ct_re.search(line)
                                meta = meta_re.search(line)
                                tags: List[str] = []
                                if meta:
                                    tags = [t.strip().lower()
                                            for t in meta.group(1).split(",")]
                                self._rule_meta_cache[sid] = {
                                    "classtype": ct.group(1) if ct else "",
                                    "metadata_tags": tags,
                                }
                    except Exception:
                        continue
        except Exception as e:
            self.logger.debug("Rule metadata scan failed: %s", e)
        self.logger.info("Indexed metadata for %d SIDs",
                         len(self._rule_meta_cache))


# ============================================================
# MODULE 2: HEALTH CHECK + ROLLBACK
# ============================================================

class ConfigBackup:
    """
    Atomic backup/restore for Suricata config files.
    Each apply cycle creates a 'generation' so rollback can be
    targeted. Uses copy2 to preserve permissions/timestamps.
    """

    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.tracked_keys = ("threshold_file", "suppress_file",
                             "pass_rules_file", "custom_rules_file")
        self.retention = cfg["health"].get("backup_retention", 10)
        self._stack: List[Dict[str, str]] = []

    def snapshot(self) -> Dict[str, str]:
        """Create a generation backup; returns {key: backup_path}."""
        ts = int(time.time() * 1000)
        gen: Dict[str, str] = {}
        for key in self.tracked_keys:
            path = self.cfg["paths"].get(key)
            if not path or not os.path.exists(path):
                continue
            backup = f"{path}.backup.{ts}"
            try:
                shutil.copy2(path, backup)
                gen[key] = backup
            except Exception as e:
                self.logger.error("Backup failed for %s: %s", path, e)
        if gen:
            self._stack.append(gen)
            self.logger.info("Config snapshot created (generation %d, %d files)",
                             len(self._stack), len(gen))
        self._prune_old_backups()
        return gen

    def restore_latest(self) -> bool:
        """Restore most recent generation. Returns True on success."""
        if not self._stack:
            self.logger.error("No backup generation to restore from")
            return False
        gen = self._stack.pop()
        ok = True
        for key, backup in gen.items():
            path = self.cfg["paths"].get(key)
            if not path or not os.path.exists(backup):
                continue
            try:
                shutil.copy2(backup, path)
                self.logger.warning("Restored %s from %s", path, backup)
            except Exception as e:
                self.logger.error("Restore failed %s -> %s: %s",
                                  backup, path, e)
                ok = False
        return ok

    def _prune_old_backups(self) -> None:
        import glob
        for key in self.tracked_keys:
            path = self.cfg["paths"].get(key)
            if not path:
                continue
            backups = sorted(glob.glob(f"{path}.backup.*"))
            excess = len(backups) - self.retention
            for old in backups[:max(excess, 0)]:
                try:
                    os.remove(old)
                except OSError:
                    pass


class HealthChecker:
    """
    Verifies Suricata health after a rules reload.
    Decision: PASS / FAIL / DEGRADED. Caller decides rollback policy.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    DEGRADED = "DEGRADED"

    def __init__(self, cfg: Dict[str, Any],
                 suricata: "SuricataController",
                 logger: logging.Logger,
                 alert_window_ref: deque):
        self.cfg = cfg
        self.suricata = suricata
        self.logger = logger
        self.alert_window = alert_window_ref
        h = cfg["health"]
        self.settle = h.get("post_reload_settle_seconds", 5)
        self.observe = h.get("post_reload_observation_seconds", 30)
        self.drop_mult = h.get("drop_spike_multiplier", 3.0)
        self.min_alerts = h.get("min_alerts_after_reload", 0)
        self.check_endpoint = h.get("stats_endpoint_check", True)

    def baseline(self) -> Dict[str, Any]:
        """Capture pre-reload metrics."""
        return {
            "drops": self.suricata.get_packet_drops(),
            "alert_count": len(self.alert_window),
            "pid_alive": self._pid_alive(),
            "captured_at": datetime.now(),
        }

    def evaluate(self, baseline: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Run post-reload checks. Returns (status, reasons)."""
        reasons: List[str] = []

        time.sleep(self.settle)

        # 1. Process liveness
        if not self._pid_alive():
            reasons.append("PROCESS_DEAD")
            return self.FAIL, reasons

        # 2. Stats endpoint responds
        if self.check_endpoint:
            drops_after = self.suricata.get_packet_drops()
            if drops_after < 0:
                reasons.append("STATS_ENDPOINT_UNREACHABLE")
                return self.FAIL, reasons
        else:
            drops_after = baseline["drops"]

        # 3. Drop spike
        drops_before = max(baseline["drops"], 1)
        if drops_after > drops_before * self.drop_mult:
            reasons.append(
                f"DROP_SPIKE({drops_before}->{drops_after}, "
                f"x{drops_after / drops_before:.1f})"
            )
            return self.FAIL, reasons

        # 4. Alert flow check
        if self.min_alerts > 0:
            window_start = len(self.alert_window)
            time.sleep(self.observe)
            window_end = len(self.alert_window)
            new_alerts = window_end - window_start
            if new_alerts < self.min_alerts:
                reasons.append(
                    f"LOW_ALERT_FLOW({new_alerts} < {self.min_alerts})")
                return self.DEGRADED, reasons

        reasons.append(f"drops_delta={drops_after - drops_before}")
        return self.PASS, reasons

    def _pid_alive(self) -> bool:
        pid_file = self.cfg["paths"].get("pid_file")
        if not pid_file or not os.path.exists(pid_file):
            try:
                r = subprocess.run(["pgrep", "-x", "Suricata"],
                                   capture_output=True, timeout=3)
                return r.returncode == 0
            except Exception:
                return True
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False


# ============================================================
# CORE TUNING ENGINE
# ============================================================

class ActiveIPSTuner:
    """Real-time inline IPS tuning engine."""

    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.lock = Lock()
        self.stop_event = Event()

        self.start_time = datetime.now()
        self.last_reload = datetime.min
        self.last_state_save = datetime.now()

        self.net = NetworkMatcher(cfg["network"])
        self.suricata = SuricataController(cfg, logger)
        self.rules = RuleGenerator()
        self.protection = CriticalSigProtection(cfg, logger)
        self.backup = ConfigBackup(cfg, logger)
        self.health = HealthChecker(cfg, self.suricata, logger,
                                    self.global_alert_window if hasattr(self, 'global_alert_window') else deque(maxlen=200_000))
        self.last_health_status = HealthChecker.PASS

        # State
        self.signature_stats: Dict[int, SignatureStats] = {}
        self.auto_suppressed: Dict[int, str] = {}
        self.auto_pass_rules: Dict[str, str] = {}
        self.fn_gaps: List[dict] = []

        # Hourly safety counters
        self.suppress_this_hour = 0
        self.pass_this_hour = 0
        self.suppress_hour_start = datetime.now()
        self.pass_hour_start = datetime.now()

        # FP storm detection
        self.global_alert_window: deque = deque(maxlen=200_000)

        self._load_state()

    # ----- Persistence ---------------------------------------
    def _load_state(self) -> None:
        path = self.cfg["paths"].get("state_file")
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "rb") as f:
                state = pickle.load(f)
            self.auto_suppressed = state.get("auto_suppressed", {})
            self.auto_pass_rules = state.get("auto_pass_rules", {})
            self.logger.info("Loaded prior state: %d suppressed, %d pass rules",
                             len(self.auto_suppressed), len(self.auto_pass_rules))
        except Exception as e:
            self.logger.warning("Could not load state file: %s", e)

    def _save_state(self) -> None:
        path = self.cfg["paths"].get("state_file")
        if not path:
            return
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                pickle.dump({
                    "auto_suppressed": self.auto_suppressed,
                    "auto_pass_rules": self.auto_pass_rules,
                    "saved_at": datetime.now().isoformat(),
                }, f)
            os.replace(tmp, path)
            self.last_state_save = datetime.now()
        except Exception as e:
            self.logger.warning("Could not save state: %s", e)

    # ----- Stats updating -----------------------------------
    def _get_or_create_stats(self, sig_id: int, msg: str = "") -> SignatureStats:
        s = self.signature_stats.get(sig_id)
        if s is None:
            s = SignatureStats(sig_id=sig_id, msg=msg, first_seen=datetime.now())
            self.signature_stats[sig_id] = s
        elif msg and not s.msg:
            s.msg = msg
        return s

    def _prune_history(self) -> None:
        cutoff = datetime.now() - timedelta(
            seconds=self.cfg["intervals"]["stats_window_seconds"] * 4
        )
        max_evt = self.cfg["performance"]["max_history_events"]
        if len(self.signature_stats) > max_evt:
            to_drop = [sid for sid, s in self.signature_stats.items()
                       if s.last_seen and s.last_seen < cutoff]
            for sid in to_drop:
                del self.signature_stats[sid]

        while self.global_alert_window and self.global_alert_window[0] < cutoff:
            self.global_alert_window.popleft()

    # ----- TP analysis --------------------------------------
    def analyze_tp(self, sig_id: int, alert_data: dict) -> Tuple[float, List[str]]:
        s = self.signature_stats[sig_id]
        src = alert_data.get("src_ip", "")
        dst = alert_data.get("dest_ip", "")
        sev = alert_data.get("alert", {}).get("severity", 3)

        score = 0.0
        reasons: List[str] = []

        if self.net.is_critical(dst):
            score += 0.40
            reasons.append("CRITICAL_SERVER_TARGETED")
        if self.net.is_threat_intel(src):
            score += 0.50
            reasons.append("THREAT_INTEL_MATCH")
        if len(s.src_ips) > 3:
            score += 0.20
            reasons.append("MULTIPLE_SOURCES")
        if sev <= 2:
            score += 0.20
            reasons.append("HIGH_SEVERITY")
        if s.src_ips.get(src, 0) > 5:
            score += 0.20
            reasons.append("REPEATED_ATTEMPTS")

        score = min(score, 1.0)

        if score >= self.cfg["thresholds"]["tp_confidence_threshold"]:
            s.classification = Classification.TRUE_POSITIVE
            s.confidence = score
            s.last_classified = datetime.now()

        return score, reasons

    # ----- FP analysis --------------------------------------
    def analyze_fp(self, sig_id: int, alert_data: dict) -> Tuple[int, List[str]]:
        s = self.signature_stats[sig_id]
        src = alert_data.get("src_ip", "")
        dst = alert_data.get("dest_ip", "")
        port = alert_data.get("dest_port", 0)

        score = 0
        reasons: List[str] = []

        if self.net.is_internal(src) and self.net.is_internal(dst):
            score += 3
            reasons.append("INTERNAL_TO_INTERNAL")

        rate = s.rate_per_hour(self.cfg["intervals"]["stats_window_seconds"])
        if rate > self.cfg["thresholds"]["fp_threshold_per_hour"]:
            score += 3
            reasons.append(f"HIGH_FREQUENCY({rate:.0f}/h)")

        if len(s.src_ips) == 1 and len(s.dst_ips) == 1:
            score += 2
            reasons.append("SINGLE_SRC_DST_PAIR")

        if self.net.is_trusted_scanner(src):
            score += 5
            reasons.append("TRUSTED_SCANNER")

        app = self.net.matching_trusted_app(src, port)
        if app:
            score += 4
            reasons.append(f"TRUSTED_APP({app})")

        if score >= self.cfg["thresholds"]["fp_score_threshold"]:
            s.classification = Classification.FALSE_POSITIVE
            s.confidence = min(score / 10.0, 1.0)
            s.last_classified = datetime.now()

        return score, reasons

    # ----- TN verification ----------------------------------
    def verify_tn(self) -> List[dict]:
        results = []
        pass_content = self._read_file_safe(self.cfg["paths"]["pass_rules_file"])
        for app, conf in self.cfg["network"]["trusted_applications"].items():
            for ip in conf.get("ips", []):
                for port in conf.get("ports", []):
                    exists = (ip in pass_content) and (str(port) in pass_content)
                    results.append({
                        "app": app, "ip": ip, "port": port,
                        "pass_rule_exists": exists,
                        "status": "TN_VERIFIED" if exists else "TN_GAP",
                    })
        return results

    # ----- FN detection -------------------------------------
    def detect_fn(self) -> List[dict]:
        findings: List[dict] = []

        drops = self.suricata.get_packet_drops()
        if drops > 0:
            findings.append({
                "type": "PACKET_DROPS", "severity": "HIGH",
                "detail": f"{drops} packets dropped — potential FNs",
                "fix": "Increase Suricata resources or reduce ruleset",
            })

        disabled = self._check_disabled_critical_rules()
        if disabled:
            findings.append({
                "type": "RULES_DISABLED", "severity": "MEDIUM",
                "detail": f"{len(disabled)} critical rules disabled",
                "fix": "Review and enable appropriate rules",
                "samples": disabled[:5],
            })

        broad = self._check_broad_pass_rules()
        if broad:
            findings.append({
                "type": "BROAD_PASS_RULES", "severity": "LOW",
                "detail": f"{len(broad)} pass rules may be too broad",
                "fix": "Tighten pass rule scoping",
                "samples": broad[:5],
            })

        if len(self.global_alert_window) > self.cfg["thresholds"]["fp_storm_threshold"]:
            findings.append({
                "type": "FP_STORM", "severity": "HIGH",
                "detail": f"{len(self.global_alert_window)} alerts in window — FP storm",
                "fix": "Real threats may be obscured; suppress noisy sigs",
            })

        return findings

    # ----- Action generation --------------------------------
    def generate_actions(self) -> List[TuningAction]:
        actions: List[TuningAction] = []
        cfg_a = self.cfg["actions"]
        cfg_t = self.cfg["thresholds"]

        for sig_id, s in self.signature_stats.items():
            if s.classification == Classification.FALSE_POSITIVE \
                    and s.confidence >= cfg_t["fp_confidence_threshold"]:
                # Critical signature protection gate
                allowed, block_reason = self.protection.can_suppress(sig_id, s)
                if not allowed:
                    self.logger.warning(
                        "BLOCKED suppress sig=%s (%s) — %s | confidence=%.2f",
                        sig_id, s.msg[:60], block_reason, s.confidence)
                    s.action_taken = f"BLOCKED:{block_reason}"
                    continue
                if (cfg_a["auto_suppress_fp"]
                        and self.suppress_this_hour < cfg_a["max_auto_suppress_per_hour"]
                        and sig_id not in self.auto_suppressed):
                    src = next(iter(s.src_ips)) if len(s.src_ips) == 1 else None
                    dst = next(iter(s.dst_ips)) if len(s.dst_ips) == 1 else None
                    rule = self.rules.suppress(sig_id, src, dst)
                    actions.append(TuningAction(
                        type="SUPPRESS", sig_id=sig_id, rule=rule,
                        reason=f"FP confidence {s.confidence:.2f}"))

            elif s.classification == Classification.TRUE_POSITIVE \
                    and s.confidence >= cfg_t["tp_confidence_threshold"]:
                if not s.action_taken:
                    rule = self.rules.threshold(sig_id, "limit", 1, 60)
                    actions.append(TuningAction(
                        type="PRIORITIZE", sig_id=sig_id, rule=rule,
                        reason=f"TP confirmed (conf {s.confidence:.2f})"))

        # FN alerts
        if self.cfg["notifications"]["alert_on_fn_detected"]:
            for f in self.detect_fn():
                if f["severity"] in ("HIGH", "MEDIUM"):
                    actions.append(TuningAction(
                        type="FN_ALERT", severity=f["severity"],
                        detail=f["detail"], fix=f["fix"]))

        # TN gap fillers
        if cfg_a["auto_bypass_trusted"]:
            for tn in self.verify_tn():
                if tn["status"] == "TN_GAP":
                    if self.pass_this_hour >= cfg_a["max_auto_pass_per_hour"]:
                        break
                    rule = self.rules.pass_rule(tn["ip"], tn["port"], tn["app"])
                    key = f"{tn['app']}:{tn['ip']}:{tn['port']}"
                    if key in self.auto_pass_rules:
                        continue
                    actions.append(TuningAction(
                        type="CREATE_PASS", rule=rule, app=tn["app"],
                        reason=f"Trusted app {tn['app']} had no pass rule"))

        return actions

    # ----- MODULE 3: APPLY-WITH-SAFETY WRAPPER --------------
    def apply_actions(self, actions: List[TuningAction]) -> None:
        """Snapshot -> write -> reload -> health check -> rollback if bad."""
        if not actions:
            return

        if self.cfg["actions"].get("learning_mode"):
            self.logger.info("[LEARNING-MODE] Would apply %d actions", len(actions))
            return

        # 1. Bucketize actions and dedupe against existing file contents
        buckets = self._bucketize_actions(actions)
        if not any(buckets.values()):
            self.logger.info("All actions deduped against existing config")
            return

        # 2. Snapshot BEFORE any writes
        snapshot_taken = False
        if self.cfg["health"].get("enabled") and not self.cfg["actions"].get("dry_run"):
            gen = self.backup.snapshot()
            snapshot_taken = bool(gen)

        # 3. Write per file
        write_results: Dict[str, bool] = {}
        file_map = {
            "threshold": self.cfg["paths"]["threshold_file"],
            "suppress":  self.cfg["paths"]["suppress_file"],
            "pass":      self.cfg["paths"]["pass_rules_file"],
        }
        for kind, lines in buckets.items():
            if not lines:
                continue
            write_results[kind] = self._append_to_file(file_map[kind], lines)

        wrote_anything = any(write_results.values())

        # 4. Bookkeeping for committed actions
        committed_actions: List[TuningAction] = []
        for a in actions:
            bucket = self._action_bucket(a)
            if bucket and write_results.get(bucket):
                self._commit_action_bookkeeping(a)
                committed_actions.append(a)
            elif a.type == "FN_ALERT":
                self.logger.warning("FN [%s]: %s | Fix: %s",
                                    a.severity, a.detail, a.fix)

        if not wrote_anything:
            return

        # 5. Reload + health check
        cooldown_ok = ((datetime.now() - self.last_reload).total_seconds()
                       > self.cfg["intervals"]["reload_cooldown"])
        if not cooldown_ok:
            self.logger.info("Reload cooldown active; rules staged for next cycle")
            return

        if not self.cfg["health"].get("enabled"):
            if self.suricata.reload_rules():
                self.last_reload = datetime.now()
            return

        baseline = self.health.baseline()
        if not self.suricata.reload_rules():
            self.logger.error("Reload command failed — rolling back")
            self._do_rollback(committed_actions, snapshot_taken)
            return

        status, reasons = self.health.evaluate(baseline)
        self.last_health_status = status
        self.logger.info("Post-reload health: %s | %s",
                         status, "; ".join(reasons))

        if status == HealthChecker.FAIL and \
                self.cfg["health"].get("rollback_on_failure", True):
            self.logger.critical(
                "HEALTH CHECK FAILED (%s) — initiating rollback", reasons)
            self._do_rollback(committed_actions, snapshot_taken)
        else:
            self.last_reload = datetime.now()
            if status == HealthChecker.DEGRADED:
                self.logger.warning(
                    "Post-reload DEGRADED — keeping changes but "
                    "increasing observation")

    def _bucketize_actions(self, actions: List[TuningAction]
                           ) -> Dict[str, List[str]]:
        """Group action rule strings, dropping duplicates already in files."""
        buckets: Dict[str, List[str]] = {
            "threshold": [], "suppress": [], "pass": []}
        existing = {
            "threshold": self._read_file_safe(self.cfg["paths"]["threshold_file"]),
            "suppress":  self._read_file_safe(self.cfg["paths"]["suppress_file"]),
            "pass":      self._read_file_safe(self.cfg["paths"]["pass_rules_file"]),
        }
        seen: Dict[str, set] = {k: set() for k in buckets}

        for a in actions:
            bucket = self._action_bucket(a)
            if not bucket or not a.rule:
                continue
            canonical = a.rule.split("#", 1)[0].strip()
            if not canonical:
                continue
            if canonical in seen[bucket]:
                continue
            if canonical and canonical in existing[bucket]:
                self.logger.debug("Dedup: rule already present in %s", bucket)
                continue
            if bucket in ("suppress", "threshold") and a.sig_id is not None:
                sid_token = f"sig_id {a.sig_id}"
                if sid_token in existing[bucket] and bucket == "suppress":
                    self.logger.debug(
                        "Dedup: sig_id %s already suppressed", a.sig_id)
                    continue
            seen[bucket].add(canonical)
            buckets[bucket].append(a.rule)
        return buckets

    @staticmethod
    def _action_bucket(a: TuningAction) -> Optional[str]:
        return {"SUPPRESS": "suppress",
                "PRIORITIZE": "threshold",
                "CREATE_PASS": "pass"}.get(a.type)

    def _commit_action_bookkeeping(self, a: TuningAction) -> None:
        if a.type == "SUPPRESS" and a.sig_id is not None and a.rule:
            self.auto_suppressed[a.sig_id] = a.rule
            s = self.signature_stats.get(a.sig_id)
            if s:
                s.action_taken = "SUPPRESSED"
            self.suppress_this_hour += 1
        elif a.type == "PRIORITIZE" and a.sig_id is not None:
            s = self.signature_stats.get(a.sig_id)
            if s:
                s.action_taken = "PRIORITIZED"
        elif a.type == "CREATE_PASS" and a.app and a.rule:
            self.auto_pass_rules[a.app] = a.rule
            self.pass_this_hour += 1

    def _undo_action_bookkeeping(self, actions: List[TuningAction]) -> None:
        """Reverse in-memory tracking when actions are rolled back."""
        for a in actions:
            if a.type == "SUPPRESS" and a.sig_id is not None:
                self.auto_suppressed.pop(a.sig_id, None)
                s = self.signature_stats.get(a.sig_id)
                if s and s.action_taken == "SUPPRESSED":
                    s.action_taken = "ROLLED_BACK"
                self.suppress_this_hour = max(0, self.suppress_this_hour - 1)
            elif a.type == "PRIORITIZE" and a.sig_id is not None:
                s = self.signature_stats.get(a.sig_id)
                if s and s.action_taken == "PRIORITIZED":
                    s.action_taken = "ROLLED_BACK"
            elif a.type == "CREATE_PASS" and a.app:
                self.auto_pass_rules.pop(a.app, None)
                self.pass_this_hour = max(0, self.pass_this_hour - 1)

    def _do_rollback(self, committed_actions: List[TuningAction],
                     snapshot_taken: bool) -> None:
        """Restore on-disk config and reverse in-memory bookkeeping."""
        self._undo_action_bookkeeping(committed_actions)
        if snapshot_taken and self.backup.restore_latest():
            if self.suricata.reload_rules():
                self.logger.warning(
                    "Rollback complete — pausing tuner for 5 minutes")
                self.last_reload = datetime.now() + timedelta(minutes=5)
            else:
                self.logger.critical(
                    "Rollback restored files but reload failed — "
                    "MANUAL INTERVENTION REQUIRED")
        else:
            self.logger.critical(
                "ROLLBACK FAILED (snapshot=%s) — MANUAL INTERVENTION REQUIRED",
                snapshot_taken)

    # ----- File helpers -------------------------------------
    def _read_file_safe(self, path: str) -> str:
        try:
            with open(path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return ""
        except Exception as e:
            self.logger.warning("Read failed %s: %s", path, e)
            return ""

    def _append_to_file(self, path: str, lines: List[str]) -> bool:
        if self.cfg["actions"].get("dry_run"):
            self.logger.info("[DRY-RUN] Would append %d lines to %s",
                             len(lines), path)
            for ln in lines:
                self.logger.debug("    %s", ln)
            return False
        with self.lock:
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                if (os.path.exists(path)
                        and os.path.getsize(path)
                        > self.cfg["performance"]["max_config_file_size"]):
                    self._rotate_file(path)
                with open(path, "a") as f:
                    for ln in lines:
                        f.write(ln.rstrip("\n") + "\n")
                self.logger.info("Wrote %d rule(s) to %s", len(lines), path)
                return True
            except Exception as e:
                self.logger.error("Failed to write %s: %s", path, e)
                return False

    def _rotate_file(self, path: str) -> None:
        backup = f"{path}.bak.{int(time.time())}"
        try:
            os.rename(path, backup)
            self.logger.info("Rotated %s -> %s", path, backup)
        except Exception as e:
            self.logger.warning("Rotate failed: %s", e)

    def _check_disabled_critical_rules(self) -> List[str]:
        out: List[str] = []
        rules_dir = self.cfg["paths"]["rules_dir"]
        if not os.path.isdir(rules_dir):
            return out
        try:
            for root, _, files in os.walk(rules_dir):
                for fname in files:
                    if not fname.endswith(".rules"):
                        continue
                    full = os.path.join(root, fname)
                    try:
                        with open(full, "r", errors="ignore") as f:
                            for line in f:
                                if line.startswith("#alert") and "priority:1" in line:
                                    out.append(line.strip()[:120])
                                    if len(out) > 1000:
                                        return out
                    except Exception:
                        continue
        except Exception as e:
            self.logger.debug("Rule scan error: %s", e)
        return out

    def _check_broad_pass_rules(self) -> List[str]:
        out: List[str] = []
        content = self._read_file_safe(self.cfg["paths"]["pass_rules_file"])
        for line in content.splitlines():
            stripped = line.strip()
            if (stripped.startswith("pass")
                    and "any any -> any any" in stripped):
                out.append(stripped)
        return out

    # ----- Status reporting ---------------------------------
    def print_status(self) -> None:
        tp = sum(1 for s in self.signature_stats.values()
                 if s.classification == Classification.TRUE_POSITIVE)
        fp = sum(1 for s in self.signature_stats.values()
                 if s.classification == Classification.FALSE_POSITIVE)
        unk = sum(1 for s in self.signature_stats.values()
                  if s.classification == Classification.UNKNOWN)
        self.logger.info(
            "STATUS  TP=%d FP=%d UNK=%d  | suppressed=%d  pass=%d  "
            "fn_gaps=%d  alerts/window=%d  health=%s",
            tp, fp, unk, len(self.auto_suppressed),
            len(self.auto_pass_rules), len(self.fn_gaps),
            len(self.global_alert_window), self.last_health_status)

    # ----- Hourly counter rollover --------------------------
    def _rollover_counters(self) -> None:
        now = datetime.now()
        if (now - self.suppress_hour_start).total_seconds() > 3600:
            self.suppress_this_hour = 0
            self.suppress_hour_start = now
        if (now - self.pass_hour_start).total_seconds() > 3600:
            self.pass_this_hour = 0
            self.pass_hour_start = now

    # ----- Eve.json processing ------------------------------
    def _process_event(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if event.get("event_type") != "alert":
            return

        alert = event.get("alert", {}) or {}
        sig_id = alert.get("signature_id")
        if not sig_id:
            return
        try:
            sig_id = int(sig_id)
        except (TypeError, ValueError):
            return

        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")
        dest_port = event.get("dest_port", 0) or 0
        msg = alert.get("signature", "")

        s = self._get_or_create_stats(sig_id, msg)
        now = datetime.now()
        s.count += 1
        s.last_seen = now
        s.recent_timestamps.append(now)
        if src_ip:
            s.src_ips[src_ip] += 1
        if dest_ip:
            s.dst_ips[dest_ip] += 1
        if dest_port:
            s.dst_ports[dest_port] += 1
        sev = alert.get("severity")
        if sev is not None:
            s.severities[sev] += 1
        self.global_alert_window.append(now)

        alert_data = {
            "src_ip": src_ip, "dest_ip": dest_ip,
            "dest_port": dest_port, "alert": alert,
            "timestamp": event.get("timestamp"),
        }

        tp_conf, _ = self.analyze_tp(sig_id, alert_data)
        fp_score, _ = self.analyze_fp(sig_id, alert_data)
        if (fp_score >= self.cfg["thresholds"]["fp_score_threshold"]
                and tp_conf < 0.4):
            s.classification = Classification.FALSE_POSITIVE
        elif (tp_conf >= self.cfg["thresholds"]["tp_confidence_threshold"]
                and fp_score < self.cfg["thresholds"]["fp_score_threshold"]):
            s.classification = Classification.TRUE_POSITIVE

    # ----- Tail log file with rotation handling -------------
    def _follow_log(self, path: str):
        """Generator that yields lines from `path`, handling rotation."""
        while not self.stop_event.is_set():
            if not os.path.exists(path):
                self.logger.info("Waiting for log file: %s", path)
                time.sleep(2)
                continue
            try:
                inode = os.stat(path).st_ino
                with open(path, "r", errors="ignore") as f:
                    f.seek(0, os.SEEK_END)
                    while not self.stop_event.is_set():
                        line = f.readline()
                        if line:
                            yield line
                            continue
                        try:
                            if os.stat(path).st_ino != inode:
                                self.logger.info("Log file rotated, reopening")
                                break
                        except FileNotFoundError:
                            break
                        time.sleep(0.5)
            except Exception as e:
                self.logger.error("Tail error: %s", e)
                time.sleep(2)

    # ----- Main loop ----------------------------------------
    def run(self) -> None:
        self.logger.info("=" * 60)
        self.logger.info("ACTIVE IPS TUNING DAEMON STARTED")
        self.logger.info("Monitoring : %s", self.cfg["paths"]["eve_log"])
        self.logger.info("Analysis interval : %ds",
                         self.cfg["intervals"]["analysis_interval"])
        self.logger.info("Mode : %s",
                         "DRY-RUN" if self.cfg["actions"].get("dry_run")
                         else ("LEARNING" if self.cfg["actions"].get("learning_mode")
                               else "ACTIVE"))
        self.logger.info("=" * 60)

        last_analysis = datetime.now()
        analysis_interval = self.cfg["intervals"]["analysis_interval"]
        save_interval = self.cfg["intervals"]["state_save_interval"]

        for line in self._follow_log(self.cfg["paths"]["eve_log"]):
            if self.stop_event.is_set():
                break

            self._process_event(line)

            now = datetime.now()
            if (now - last_analysis).total_seconds() >= analysis_interval:
                self._run_analysis_cycle()
                last_analysis = now

            if (now - self.last_state_save).total_seconds() >= save_interval:
                self._save_state()

        self._save_state()
        self.logger.info("Tuning daemon stopped cleanly")

    def _run_analysis_cycle(self) -> None:
        self.logger.info("--- Running analysis cycle ---")
        self._prune_history()
        self._rollover_counters()
        actions = self.generate_actions()
        self.print_status()
        if actions:
            self.logger.info("Generated %d tuning actions", len(actions))
            for a in actions:
                if a.type == "SUPPRESS":
                    self.logger.info("  [SUPPRESS]   sig=%s  %s", a.sig_id, a.reason)
                elif a.type == "PRIORITIZE":
                    self.logger.info("  [PRIORITIZE] sig=%s  %s", a.sig_id, a.reason)
                elif a.type == "CREATE_PASS":
                    self.logger.info("  [PASS]       app=%s", a.app)
                elif a.type == "FN_ALERT":
                    self.logger.warning("  [FN-ALERT]   %s: %s",
                                        a.severity, a.detail)
            self.apply_actions(actions)
        else:
            self.logger.info("  No tuning actions needed")

    def shutdown(self) -> None:
        self.logger.info("Shutdown requested")
        self.stop_event.set()


# ============================================================
# ENTRY POINT
# ============================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Active inline IPS tuning daemon for Suricata",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-c", "--config", help="Path to YAML config file")
    p.add_argument("--dry-run", action="store_true",
                   help="Classify and log, but do not write any rules")
    p.add_argument("--learning-mode", action="store_true",
                   help="Observe and classify only; never apply actions")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("--print-config", action="store_true",
                   help="Print effective config and exit")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)

    if args.dry_run:
        cfg["actions"]["dry_run"] = True
    if args.learning_mode:
        cfg["actions"]["learning_mode"] = True

    if args.print_config:
        print(json.dumps(cfg, indent=2, default=str))
        return 0

    logger = setup_logging(cfg, args.verbose)
    tuner = ActiveIPSTuner(cfg, logger)

    def _sig_handler(signum, _frame):
        logger.info("Signal %d received", signum)
        tuner.shutdown()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        tuner.run()
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
