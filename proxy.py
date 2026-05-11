"""SOCKS5 proxy with DPI-bypass engine.

Implements RFC 1928 SOCKS5 (no authentication, CONNECT only) and applies
TCP fragmentation, fake-TLS junk injection, and HTTP Host case toggling
to the first outbound payload chunk on a per-connection basis.

The proxy is fully user-space; no raw sockets or root privileges required.
"""

from __future__ import annotations

import logging
import random
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("dpibypass.proxy")

# A short, syntactically-valid-looking but meaningless TLS record. Sent before
# the real ClientHello to desync stateful DPI parsers that latch onto the
# first record they see on a flow.
FAKE_TLS_RECORD = b"\x16\x03\x01\x00\x05\x00\x00\x00\x00\x00"

BUFFER_SIZE = 65535
SOCKS_VERSION = 0x05


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8881
    frag_size: int = 2  # bytes per fragment for non-TLS first payload
    junk_enabled: bool = False  # prepending a fake TLS record usually breaks TLS
    host_case_toggle: bool = True
    split_at_sni: bool = True  # split TLS ClientHello inside SNI hostname
    tls_record_split: bool = True  # split into two TLS records (defeats TCP-reassembling DPI)
    oob_enabled: bool = False  # OOB byte between halves (some DPIs RST on this)
    block_quic: bool = False  # handled outside the SOCKS path
    fragment_domains: frozenset = frozenset()  # hosts to DPI-bypass; empty = bypass all
    vless_router: Optional[Any] = field(default=None, repr=False)  # VlessRouter instance
    log_callback: Optional[Callable[[str], None]] = field(default=None, repr=False)


def _domain_uses_bypass(host: str, domains: frozenset) -> bool:
    """Return True when *host* should use DPI-bypass (fragment/split).

    If *domains* is empty every host is bypassed (backward-compatible mode).
    A domain entry matches the host itself **and** all its subdomains.
    """
    if not domains:
        return True
    host = host.lower().split(":")[0]
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in domains:
            return True
    return False


def _emit(cfg: ProxyConfig, msg: str) -> None:
    logger.info(msg)
    if cfg.log_callback:
        try:
            cfg.log_callback(msg)
        except Exception:  # pragma: no cover - GUI must never kill proxy
            pass


def _looks_like_tls_client_hello(data: bytes) -> bool:
    # TLS record: type=0x16 (handshake), version 0x0301..0x0304, then length,
    # then handshake type 0x01 (ClientHello).
    return (
        len(data) >= 6
        and data[0] == 0x16
        and data[1] == 0x03
        and data[5] == 0x01
    )


def _looks_like_http(data: bytes) -> bool:
    head = data[:8].upper()
    return head.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS", b"PATCH ", b"CONNECT"))


def _find_sni_range(data: bytes) -> Optional[tuple[int, int]]:
    """Return (offset, length) of the SNI hostname inside a ClientHello."""
    try:
        if not _looks_like_tls_client_hello(data):
            return None
        p = 5 + 4 + 2 + 32  # record + handshake + version + random
        sid_len = data[p]; p += 1 + sid_len
        cs_len = struct.unpack(">H", data[p:p + 2])[0]; p += 2 + cs_len
        cm_len = data[p]; p += 1 + cm_len
        ext_total = struct.unpack(">H", data[p:p + 2])[0]; p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", data[p:p + 4])
            p += 4
            if etype == 0x00:  # server_name
                name_type = data[p + 2]
                if name_type == 0:
                    name_len = struct.unpack(">H", data[p + 3:p + 5])[0]
                    return (p + 5, name_len)
            p += elen
    except Exception:
        return None
    return None


def _extract_sni(data: bytes) -> Optional[str]:
    rng = _find_sni_range(data)
    if rng is None:
        return None
    off, ln = rng
    try:
        return data[off:off + ln].decode("ascii", "replace")
    except Exception:
        return None


def _extract_http_host(data: bytes) -> Optional[str]:
    try:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        for line in head.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        return None
    return None


def _toggle_http_host_case(data: bytes) -> bytes:
    """Randomize the case of the literal token 'Host' in the request header."""
    try:
        sep = b"\r\n\r\n"
        if sep not in data:
            return data
        head, body = data.split(sep, 1)
        lines = head.split(b"\r\n")
        for i, line in enumerate(lines):
            if line[:5].lower() == b"host:":
                rest = line[4:]
                scrambled = bytes(
                    (c ^ 0x20) if chr(c).isalpha() and random.random() < 0.5 else c
                    for c in b"Host"
                )
                lines[i] = scrambled + rest
                break
        return b"\r\n".join(lines) + sep + body
    except Exception:
        return data


def _enable_nodelay(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def _send_oob(sock: socket.socket) -> None:
    """Send a single out-of-band byte. Many DPIs mishandle OOB and desync."""
    try:
        sock.send(b"\xff", socket.MSG_OOB)
    except OSError:
        pass


def _send_fragmented(sock: socket.socket, data: bytes, frag_size: int, junk: bool) -> None:
    """Plain even fragmentation, used for non-TLS payloads."""
    _enable_nodelay(sock)
    if junk:
        try:
            sock.sendall(FAKE_TLS_RECORD)
        except OSError:
            return
    step = max(1, min(frag_size, 10))
    for i in range(0, len(data), step):
        chunk = data[i:i + step]
        try:
            sock.sendall(chunk)
        except OSError:
            return
        if i + step < len(data):
            time.sleep(0.004)


def _build_tls_record(payload: bytes, version: bytes) -> bytes:
    return b"\x16" + version + struct.pack(">H", len(payload)) + payload


def _split_clienthello_into_records(data: bytes, split_at_sni: bool, frag_size: int) -> Optional[tuple[bytes, bytes]]:
    """Split a single ClientHello TLS record into two valid TLS records.

    The TLS spec allows one handshake message to be carried across multiple
    records, and Google's servers accept this. DPI engines that match SNI
    against a single TLS record (without cross-record reassembly) cannot
    see the full hostname and fail to match.
    """
    if len(data) < 6 or data[0] != 0x16:
        return None
    version = data[1:3]
    rec_len = struct.unpack(">H", data[3:5])[0]
    if 5 + rec_len > len(data):
        return None
    payload = data[5:5 + rec_len]
    tail = data[5 + rec_len:]  # usually empty for a fresh ClientHello

    split_in_payload: Optional[int] = None
    if split_at_sni:
        rng = _find_sni_range(data)
        if rng is not None:
            sni_off, sni_len = rng
            if sni_len >= 4:
                # offset inside `data`; convert to offset inside `payload`.
                split_in_payload = (sni_off - 5) + max(1, sni_len // 2)
    if split_in_payload is None or not (0 < split_in_payload < len(payload)):
        split_in_payload = max(1, min(frag_size, len(payload) - 1))

    p1 = payload[:split_in_payload]
    p2 = payload[split_in_payload:]
    rec1 = _build_tls_record(p1, version)
    rec2 = _build_tls_record(p2, version)
    return rec1, rec2 + tail


def _send_tls_split(sock: socket.socket, data: bytes, cfg: "ProxyConfig") -> None:
    """Apply TLS record split (preferred) or TCP byte split as fallback."""
    _enable_nodelay(sock)

    if cfg.junk_enabled:
        try:
            sock.sendall(FAKE_TLS_RECORD)
        except OSError:
            return

    if cfg.tls_record_split:
        pair = _split_clienthello_into_records(data, cfg.split_at_sni, cfg.frag_size)
        if pair is not None:
            rec1, rec2 = pair
            try:
                sock.sendall(rec1)
            except OSError:
                return
            if cfg.oob_enabled:
                _send_oob(sock)
            time.sleep(0.005)
            try:
                sock.sendall(rec2)
            except OSError:
                return
            return

    # Fallback: TCP-level split.
    split_pos: Optional[int] = None
    if cfg.split_at_sni:
        rng = _find_sni_range(data)
        if rng is not None:
            off, ln = rng
            if ln >= 4:
                split_pos = off + max(1, ln // 2)
    if split_pos is None:
        split_pos = max(1, min(cfg.frag_size, len(data) - 1))

    first, second = data[:split_pos], data[split_pos:]
    try:
        sock.sendall(first)
    except OSError:
        return
    if cfg.oob_enabled:
        _send_oob(sock)
    time.sleep(0.005)
    try:
        sock.sendall(second)
    except OSError:
        return


class SocksProxyServer:
    """Threaded SOCKS5 server with DPI-bypass first-payload mangling."""

    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._connections = 0
        self._lock = threading.Lock()

    # ---- lifecycle -----------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.cfg.host, self.cfg.port))
        self._srv.listen(128)
        self._srv.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, name="socks5-accept", daemon=True)
        self._thread.start()
        _emit(self.cfg, f"[+] SOCKS5 listening on {self.cfg.host}:{self.cfg.port}")

    def stop(self) -> None:
        self._stop.set()
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        _emit(self.cfg, "[-] SOCKS5 stopped")

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._connections

    # ---- server loop ---------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._srv
        while not self._stop.is_set():
            try:
                client, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
            t.start()

    # ---- per-connection handler ---------------------------------------
    def _handle_client(self, client: socket.socket, addr) -> None:
        with self._lock:
            self._connections += 1
        remote: Optional[socket.socket] = None
        try:
            client.settimeout(10.0)
            if not self._socks_handshake(client):
                return
            remote_addr = self._socks_request(client)
            if remote_addr is None:
                return
            host, port = remote_addr
            use_bypass = _domain_uses_bypass(host, self.cfg.fragment_domains)
            vr = self.cfg.vless_router
            if use_bypass or not (vr is not None and vr.running):
                try:
                    remote = socket.create_connection((host, port), timeout=10.0)
                except OSError as e:
                    _emit(self.cfg, f"[!] connect failed {host}:{port}: {e}")
                    self._send_socks_reply(client, 0x05)
                    return
            else:
                remote = vr.connect(host, port)
                if remote is None:
                    _emit(self.cfg, f"[!] vless connect failed {host}:{port}")
                    self._send_socks_reply(client, 0x05)
                    return

            # SOCKS5 success reply with bound address (use 0.0.0.0:0).
            self._send_socks_reply(client, 0x00)
            client.settimeout(None)
            remote.settimeout(None)
            if use_bypass:
                self._splice(client, remote, host, port)
            else:
                self._splice_plain(client, remote)
        except Exception as e:  # pragma: no cover
            _emit(self.cfg, f"[!] connection error: {e}")
        finally:
            for s in (client, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            with self._lock:
                self._connections -= 1

    # ---- SOCKS5 protocol ----------------------------------------------
    def _socks_handshake(self, client: socket.socket) -> bool:
        header = self._recv_exact(client, 2)
        if not header or header[0] != SOCKS_VERSION:
            return False
        nmethods = header[1]
        methods = self._recv_exact(client, nmethods)
        if methods is None:
            return False
        # Accept "no auth" (0x00) only.
        if 0x00 not in methods:
            client.sendall(bytes([SOCKS_VERSION, 0xFF]))
            return False
        client.sendall(bytes([SOCKS_VERSION, 0x00]))
        return True

    def _socks_request(self, client: socket.socket):
        hdr = self._recv_exact(client, 4)
        if not hdr or hdr[0] != SOCKS_VERSION:
            return None
        cmd, _, atyp = hdr[1], hdr[2], hdr[3]
        if cmd != 0x01:  # only CONNECT
            self._send_socks_reply(client, 0x07)
            return None
        if atyp == 0x01:  # IPv4
            raw = self._recv_exact(client, 4)
            if not raw:
                return None
            host = socket.inet_ntoa(raw)
        elif atyp == 0x03:  # domain
            ln = self._recv_exact(client, 1)
            if not ln:
                return None
            raw = self._recv_exact(client, ln[0])
            if raw is None:
                return None
            try:
                host = raw.decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                host = raw.decode("ascii", "replace")
        elif atyp == 0x04:  # IPv6
            raw = self._recv_exact(client, 16)
            if not raw:
                return None
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            self._send_socks_reply(client, 0x08)
            return None
        port_raw = self._recv_exact(client, 2)
        if not port_raw:
            return None
        port = struct.unpack(">H", port_raw)[0]
        return host, port

    def _send_socks_reply(self, client: socket.socket, rep: int) -> None:
        try:
            client.sendall(bytes([SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        except OSError:
            pass

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    # ---- bidirectional splice with first-chunk mangling ---------------
    def _splice(self, client: socket.socket, remote: socket.socket, host: str, port: int) -> None:
        first_done = False
        sockets = [client, remote]
        while True:
            try:
                r, _, x = select.select(sockets, [], sockets, 30.0)
            except (OSError, ValueError):
                return
            if x:
                return
            if not r:
                return
            for s in r:
                try:
                    data = s.recv(BUFFER_SIZE)
                except OSError:
                    return
                if not data:
                    return
                if s is client and not first_done:
                    first_done = True
                    self._dispatch_first_payload(data, remote, host, port)
                elif s is client:
                    try:
                        remote.sendall(data)
                    except OSError:
                        return
                else:  # remote -> client
                    try:
                        client.sendall(data)
                    except OSError:
                        return

    def _dispatch_first_payload(self, data: bytes, remote: socket.socket, host: str, port: int) -> None:
        cfg = self.cfg
        if _looks_like_tls_client_hello(data):
            sni = _extract_sni(data) or host
            _emit(
                cfg,
                f"[TLS] {sni}:{port} rec_split={cfg.tls_record_split} sni={cfg.split_at_sni} oob={cfg.oob_enabled} junk={cfg.junk_enabled}",
            )
            _send_tls_split(remote, data, cfg)
            return
        if _looks_like_http(data):
            http_host = _extract_http_host(data) or host
            mangled = _toggle_http_host_case(data) if cfg.host_case_toggle else data
            _emit(cfg, f"[HTTP] {http_host}:{port} host_case={cfg.host_case_toggle}")
            # Never prepend junk for HTTP: it would corrupt the request line.
            _send_fragmented(remote, mangled, cfg.frag_size, junk=False)
            return
        _emit(cfg, f"[RAW] {host}:{port}")
        try:
            remote.sendall(data)
        except OSError:
            return


    def _splice_plain(self, client: socket.socket, remote: socket.socket) -> None:
        """Bidirectional relay with no DPI-bypass mangling (used for VLESS path)."""
        sockets = [client, remote]
        while True:
            try:
                r, _, x = select.select(sockets, [], sockets, 30.0)
            except (OSError, ValueError):
                return
            if x or not r:
                return
            for s in r:
                dst = remote if s is client else client
                try:
                    data = s.recv(BUFFER_SIZE)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return


if __name__ == "__main__":  # quick CLI smoke test
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    server = SocksProxyServer(ProxyConfig())
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
