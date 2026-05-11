"""VLESS xhttp outbound router.

Manages an xray-core subprocess that exposes a local SOCKS5 inbound so that
non-fragmented traffic can be tunnelled through the VLESS xhttp link supplied
in xhttp.txt.  Also provides load_fragment_domains() to read fragmentthis.txt.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

INTERNAL_SOCKS_PORT = 8882


# ── URL parsing ────────────────────────────────────────────────────────────


def parse_vless_url(url: str) -> dict:
    """Parse a vless:// link into a plain dict of fields."""
    url = url.strip()
    p = urlparse(url)
    if p.scheme != "vless":
        raise ValueError(f"Expected vless:// URL, got: {url[:60]}")

    q = parse_qs(p.query)

    def _q(key: str, default: str = "") -> str:
        return q.get(key, [default])[0]

    return {
        "uuid":     p.username or "",
        "server":   p.hostname or "",
        "port":     p.port or 443,
        "type":     _q("type", "tcp"),
        "path":     _q("path", "/"),
        "security": _q("security", "none"),
        "sni":      _q("sni", p.hostname or ""),
        "fp":       _q("fp", ""),
        "pbk":      _q("pbk", ""),
        "sid":      _q("sid", ""),
        "spx":      _q("spx", ""),
        "flow":     _q("flow", ""),
        "host":     _q("host", p.hostname or ""),
    }


# ── Xray config builder ────────────────────────────────────────────────────


def build_xray_config(vless: dict, socks_port: int) -> dict:
    """Generate a minimal xray JSON config: SOCKS5 inbound → VLESS outbound."""
    net = vless["type"]

    stream: dict = {"network": net}

    if net == "xhttp":
        stream["xhttpSettings"] = {
            "path": vless["path"],
            "host": [vless["host"]] if vless["host"] else [],
            "mode": "auto",
        }
    elif net == "ws":
        stream["wsSettings"] = {
            "path": vless["path"],
            "headers": {"Host": vless["host"]},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": vless["path"].lstrip("/")}
    elif net == "h2":
        stream["httpSettings"] = {
            "path": vless["path"],
            "host": [vless["host"]] if vless["host"] else [],
        }

    sec = vless["security"]
    if sec == "tls":
        tls: dict = {"serverName": vless["sni"], "allowInsecure": False}
        if vless["fp"]:
            tls["fingerprint"] = vless["fp"]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": vless["sni"],
            "fingerprint": vless["fp"] or "chrome",
            "publicKey": vless["pbk"],
            "shortId": vless["sid"],
            "spiderX": vless["spx"],
        }
    else:
        stream["security"] = "none"

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": vless["server"],
                    "port": vless["port"],
                    "users": [{
                        "id": vless["uuid"],
                        "encryption": "none",
                        "flow": vless["flow"],
                        "level": 0,
                    }],
                }],
            },
            "streamSettings": stream,
            "tag": "vless-out",
        }],
    }


# ── Domain list loader ─────────────────────────────────────────────────────


def load_fragment_domains(path: str) -> frozenset:
    """Read one domain per line from *path*, ignoring comments and blanks."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            domains = set()
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower().split(":")[0])
            return frozenset(domains)
    except FileNotFoundError:
        return frozenset()


# ── Internal helpers ───────────────────────────────────────────────────────


def _find_xray() -> Optional[str]:
    for name in ("xray", "xray-linux-amd64", "xray-core"):
        p = shutil.which(name)
        if p:
            return p
    for p in ("/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _recv_n(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ── VlessRouter ────────────────────────────────────────────────────────────


class VlessRouter:
    """Wraps an xray subprocess and tunnels arbitrary TCP connections through it."""

    def __init__(
        self,
        xhttp_txt_path: str,
        socks_port: int = INTERNAL_SOCKS_PORT,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.xhttp_txt_path = xhttp_txt_path
        self.socks_port = socks_port
        self.log_callback = log_callback
        self._config_path = os.path.join(
            os.path.dirname(os.path.abspath(xhttp_txt_path)), ".xray_config.json"
        )
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self.vless_url: Optional[str] = None

    # ── public API ────────────────────────────────────────────────────────

    def set_url(self, url: str) -> None:
        """Set the VLESS URL directly from the UI (takes priority over xhttp.txt)."""
        self.vless_url = url.strip() or None

    def load_url(self) -> bool:
        """Validate the VLESS URL. Checks in-memory URL (set via set_url) first,
        then falls back to reading xhttp.txt."""
        if self.vless_url:
            try:
                parse_vless_url(self.vless_url)
                return True
            except Exception as exc:
                self._log(f"[xray] invalid VLESS URL: {exc}")
                return False
        try:
            with open(self.xhttp_txt_path, "r", encoding="utf-8") as f:
                url = f.read().strip()
            if not url or url.startswith("#"):
                self._log("[xray] xhttp.txt is empty — VLESS routing disabled")
                return False
            parse_vless_url(url)
            self.vless_url = url
            return True
        except FileNotFoundError:
            self._log(f"[xray] xhttp.txt not found — VLESS routing disabled")
            return False
        except Exception as exc:
            self._log(f"[xray] cannot parse xhttp.txt: {exc}")
            return False

    def start(self) -> bool:
        """Start the xray subprocess. Returns True if running."""
        if not self.load_url():
            return False
        with self._lock:
            if self._process and self._process.poll() is None:
                return True
            xray_bin = _find_xray()
            if not xray_bin:
                self._log("[xray] binary not found (install xray-core) — VLESS routing disabled")
                return False
            try:
                vless = parse_vless_url(self.vless_url)  # type: ignore[arg-type]
                cfg = build_xray_config(vless, self.socks_port)
                with open(self._config_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2)
                self._process = subprocess.Popen(
                    [xray_bin, "run", "-c", self._config_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except Exception as exc:
                self._log(f"[xray] launch error: {exc}")
                return False

        time.sleep(0.5)
        with self._lock:
            if self._process and self._process.poll() is not None:
                out = ""
                try:
                    out = (self._process.stdout.read() or "")[:300]  # type: ignore[union-attr]
                except Exception:
                    pass
                self._log(f"[xray] process exited immediately: {out}")
                return False

        threading.Thread(target=self._tail_logs, daemon=True).start()
        self._log(
            f"[xray] started → socks5://127.0.0.1:{self.socks_port}"
            f" (→ {vless['server']}:{vless['port']})"
        )
        return True

    def stop(self) -> None:
        with self._lock:
            p, self._process = self._process, None
        if p:
            try:
                p.terminate()
                p.wait(timeout=3.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            self._log("[xray] stopped")

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._process and self._process.poll() is None)

    def connect(self, host: str, port: int, timeout: float = 10.0) -> Optional[socket.socket]:
        """Return a socket to (host, port) already tunnelled through xray SOCKS5."""
        if not self.running:
            return None
        try:
            sock = socket.create_connection(("127.0.0.1", self.socks_port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            resp = _recv_n(sock, 2)
            if not resp or resp[1] != 0x00:
                sock.close()
                return None
            host_b = host.encode("idna")
            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(host_b)])
                + host_b
                + struct.pack(">H", port)
            )
            reply = _recv_n(sock, 10)
            if not reply or reply[1] != 0x00:
                sock.close()
                return None
            sock.settimeout(None)
            return sock
        except Exception as exc:
            self._log(f"[xray] connect {host}:{port} error: {exc}")
            return None

    # ── internal ──────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if self.log_callback:
            try:
                self.log_callback(msg)
            except Exception:
                pass

    def _tail_logs(self) -> None:
        proc = self._process
        if not proc or not proc.stdout:
            return
        try:
            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    self._log(f"[xray] {stripped}")
        except Exception:
            pass

