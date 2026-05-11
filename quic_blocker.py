"""Optional QUIC (UDP/443) blocker.

Uses iptables via pkexec (or sudo) to install/remove a REJECT rule so the
browser falls back to TCP/TLS, which then traverses the SOCKS5 proxy.

This module is best-effort: if no privilege helper is available, it returns
False and the GUI surfaces a friendly hint. No raw sockets are required for
the SOCKS5 proxy itself; only this auxiliary feature needs root.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional

RULE_ARGS = ["OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"]


def _privileged_runner() -> Optional[list[str]]:
    # Сначала проверяем sudo, так как мы настроили его в sudoers без пароля
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    # Если sudo нет (маловероятно для Arch), пробуем pkexec (вызовет окно)
    if shutil.which("pkexec"):
        return ["pkexec"]
    return None


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return proc.returncode, (proc.stderr or proc.stdout).strip()
    except Exception as e:  # pragma: no cover
        return 1, str(e)


def _iptables_cmd(action: str) -> Optional[list[str]]:
    runner = _privileged_runner()
    iptables = shutil.which("iptables")
    if not runner or not iptables:
        return None
    return [*runner, iptables, action, *RULE_ARGS]
    

def is_blocked() -> bool:
    iptables = shutil.which("iptables")
    if not iptables:
        return False
    # Раньше тут было runner = _privileged_runner() or []
    # Но для проверки правила (-C) тоже нужно использовать sudo, 
    # иначе iptables может не хватить прав прочитать текущие правила.
    runner = _privileged_runner() or []
    rc, _ = _run([*runner, iptables, "-C", *RULE_ARGS])
    return rc == 0


def enable_block() -> tuple[bool, str]:
    cmd = _iptables_cmd("-I")
    if cmd is None:
        return False, "iptables or pkexec/sudo not available"
    if is_blocked():
        return True, "already blocked"
    rc, msg = _run(cmd)
    return rc == 0, msg or "ok"


def disable_block() -> tuple[bool, str]:
    cmd = _iptables_cmd("-D")
    if cmd is None:
        return False, "iptables or pkexec/sudo not available"
    if not is_blocked():
        return True, "not active"
    rc, msg = _run(cmd)
    return rc == 0, msg or "ok"
