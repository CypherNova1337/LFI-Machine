"""
Curated target files and a canary probe used for detection and post-exploit
harvesting. Kept intentionally tight and high-signal rather than a giant fuzz
list — the engine reasons about depth and wrappers instead of brute force.
"""
from __future__ import annotations

from typing import Dict, List

# The primary detection probe per OS. ``sig`` names the signature that confirms it.
PROBES: Dict[str, List[Dict[str, str]]] = {
    "linux": [
        {"path": "etc/passwd", "sig": "etc_passwd"},
        {"path": "etc/hosts", "sig": "etc_hosts"},
        {"path": "proc/version", "sig": "proc_version"},
    ],
    "windows": [
        {"path": "windows/win.ini", "sig": "win_ini"},
        {"path": "windows/system32/drivers/etc/hosts", "sig": "windows_hosts"},
        {"path": "boot.ini", "sig": "boot_ini"},
    ],
}

# Absolute paths worth trying when traversal depth is unknown/irrelevant.
ABSOLUTE_PROBES: Dict[str, List[str]] = {
    "linux": ["/etc/passwd", "/etc/hosts", "/proc/self/cmdline"],
    "windows": [
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:/Windows/System32/drivers/etc/hosts",
    ],
}

# High-value files to pull once inclusion is confirmed. Grouped for reporting.
SENSITIVE_FILES: Dict[str, List[str]] = {
    "linux-system": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "/etc/os-release",
        "/etc/crontab",
        "/root/.bash_history",
        "/root/.ssh/id_rsa",
        "/home/*/.ssh/id_rsa",
        "/home/*/.bash_history",
    ],
    "linux-proc": [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/net/tcp",
        "/proc/mounts",
        "/proc/version",
    ],
    "linux-web": [
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/.env",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/usr/local/etc/php/php.ini",
    ],
    "windows-system": [
        "C:/Windows/win.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/System32/config/SAM",
        "C:/Windows/System32/inetsrv/config/applicationHost.config",
        "C:/inetpub/wwwroot/web.config",
        "C:/xampp/apache/conf/httpd.conf",
        "C:/xampp/php/php.ini",
    ],
    "logs": [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/mail.log",
        "/var/log/vsftpd.log",
        "C:/xampp/apache/logs/access.log",
        "C:/xampp/apache/logs/error.log",
    ],
}

# Log locations probed when attempting log-poisoning RCE.
LOG_PATHS: List[str] = [
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/mail",
    "/var/log/vsftpd.log",
    "C:/xampp/apache/logs/access.log",
    "C:/wamp/logs/access.log",
    "C:/Apache24/logs/access.log",
]


def flatten_sensitive(os_name: str | None = None) -> List[str]:
    out: List[str] = []
    for group, files in SENSITIVE_FILES.items():
        if os_name == "linux" and group.startswith("windows"):
            continue
        if os_name == "windows" and group.startswith("linux"):
            continue
        out.extend(files)
    return out
