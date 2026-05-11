"""Optional QUIC (UDP/443) blocker — Linux (iptables) / Windows (netsh).

Installs a firewall rule that drops outbound UDP/443 so the browser falls
back to TCP/TLS, which then traverses the SOCKS5 proxy.

* Linux: iptables -j REJECT, escalated via sudo/pkexec.
* Windows: netsh advfirewall firewall add rule, escalated via UAC.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from typing import Optional

_IS_WIN = sys.platform == "win32"
_NETSH_RULE = "DPIBypass_BlockQUIC"
_IPT_ARGS = ["OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"]


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return proc.returncode, (proc.stderr or proc.stdout).strip()
    except Exception as e:  # pragma: no cover
        return 1, str(e)


# ── Linux backend (iptables) ─────────────────────────────────────────────────

def _linux_runner() -> Optional[list[str]]:
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    if shutil.which("pkexec"):
        return ["pkexec"]
    return None


def _linux_is_blocked() -> bool:
    iptables = shutil.which("iptables")
    if not iptables:
        return False
    runner = _linux_runner() or []
    rc, _ = _run([*runner, iptables, "-C", *_IPT_ARGS])
    return rc == 0


def _linux_toggle(action: str) -> tuple[bool, str]:
    iptables = shutil.which("iptables")
    runner = _linux_runner()
    if not runner or not iptables:
        return False, "iptables or pkexec/sudo not available"
    rc, msg = _run([*runner, iptables, action, *_IPT_ARGS])
    return rc == 0, msg or "ok"


# ── Windows backend (netsh advfirewall) ──────────────────────────────────────

def _win_is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _win_run_elevated(args: list[str]) -> bool:
    """Run `netsh <args>` via UAC. Returns True if user accepted prompt."""
    import ctypes
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "netsh", subprocess.list2cmdline(args), None, 0
    )
    return rc > 32


def _win_is_blocked() -> bool:
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={_NETSH_RULE}"],
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0 and _NETSH_RULE in proc.stdout
    except Exception:
        return False


def _win_toggle(enable: bool) -> tuple[bool, str]:
    if enable:
        args = ["advfirewall", "firewall", "add", "rule",
                f"name={_NETSH_RULE}",
                "dir=out", "action=block", "protocol=UDP", "remoteport=443"]
    else:
        args = ["advfirewall", "firewall", "delete", "rule",
                f"name={_NETSH_RULE}"]

    if _win_is_admin():
        rc, msg = _run(["netsh", *args])
        return rc == 0, msg or "ok"
    if _win_run_elevated(args):
        time.sleep(0.5)
        applied = _win_is_blocked() if enable else not _win_is_blocked()
        return applied, "via UAC"
    return False, "UAC declined or unavailable"


# ── Public API ───────────────────────────────────────────────────────────────

def is_blocked() -> bool:
    return _win_is_blocked() if _IS_WIN else _linux_is_blocked()


def enable_block() -> tuple[bool, str]:
    if is_blocked():
        return True, "already blocked"
    return _win_toggle(True) if _IS_WIN else _linux_toggle("-I")


def disable_block() -> tuple[bool, str]:
    if not is_blocked():
        return True, "not active"
    return _win_toggle(False) if _IS_WIN else _linux_toggle("-D")
