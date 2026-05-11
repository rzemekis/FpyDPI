"""DPI Bypass SOCKS5 Proxy GUI (customtkinter)."""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime

import customtkinter as ctk
from PIL import Image, ImageDraw

import quic_blocker
from proxy import ProxyConfig, SocksProxyServer
from vless_router import load_fragment_domains

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)
_FRAG_FILE = os.path.join(_DIR, "fragmentthis.txt")


def _make_pil_icon(color: str) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    ImageDraw.Draw(img).ellipse([8, 8, 56, 56], fill=color)
    return img


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DPI Bypass — SOCKS5")
        self.geometry("720x560")
        self.minsize(600, 480)

        self._log_queue: queue.Queue[str] = queue.Queue()
        self._tray = None

        domains = load_fragment_domains(_FRAG_FILE)
        self.cfg = ProxyConfig(
            log_callback=self._on_log,
            fragment_domains=domains,
        )
        self.server = SocksProxyServer(self.cfg)

        self._build_ui()
        self._start_tray()
        self._poll_log()
        self._refresh_status()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabview.add("Dashboard")
        self.tabview.add("Settings")
        self._build_dashboard(self.tabview.tab("Dashboard"))
        self._build_settings(self.tabview.tab("Settings"))

    def _build_dashboard(self, parent: ctk.CTkFrame) -> None:
        status_row = ctk.CTkFrame(parent, fg_color="transparent")
        status_row.pack(fill="x", pady=(0, 6))
        self.status_dot = ctk.CTkLabel(status_row, text="●", font=("", 22), text_color="#cc4444")
        self.status_dot.pack(side="left", padx=(0, 6))
        self.status_label = ctk.CTkLabel(status_row, text="Disconnected", font=("", 18, "bold"))
        self.status_label.pack(side="left")
        self.conn_label = ctk.CTkLabel(status_row, text="0 connections", text_color="gray")
        self.conn_label.pack(side="right")

        self.toggle_btn = ctk.CTkButton(
            parent, text="Start", height=56, font=("", 18, "bold"),
            command=self._toggle_proxy,
        )
        self.toggle_btn.pack(fill="x", pady=6)

        routing_row = ctk.CTkFrame(parent, fg_color="transparent")
        routing_row.pack(fill="x", pady=(0, 4))
        self.domains_label = ctk.CTkLabel(routing_row, text="bypass: — domains",
                                          text_color="gray", font=("", 12))
        self.domains_label.pack(side="left")
        ctk.CTkButton(routing_row, text="↺ Reload routing", height=26, width=140,
                      command=self._reload_routing).pack(side="right")

        ctk.CTkLabel(parent, text="Log:", anchor="w").pack(fill="x")
        self.log_view = ctk.CTkTextbox(parent, state="disabled", wrap="none")
        self.log_view.pack(fill="both", expand=True)

    def _build_settings(self, parent: ctk.CTkFrame) -> None:
        scroll = ctk.CTkScrollableFrame(parent)
        scroll.pack(fill="both", expand=True)

        def lrow(label: str) -> ctk.CTkFrame:
            f = ctk.CTkFrame(scroll, fg_color="transparent")
            f.pack(fill="x", pady=3)
            ctk.CTkLabel(f, text=label, width=230, anchor="w").pack(side="left")
            return f

        f = lrow("Proxy port:")
        self.port_entry = ctk.CTkEntry(f, width=80)
        self.port_entry.insert(0, str(self.cfg.port))
        self.port_entry.pack(side="left")

        f = lrow("Fragment size (1–10):")
        self.frag_var = tk.IntVar(value=self.cfg.frag_size)
        ctk.CTkSlider(f, from_=1, to=10, number_of_steps=9,
                      variable=self.frag_var, width=160).pack(side="left", padx=6)
        self.frag_lbl = ctk.CTkLabel(f, text=str(self.cfg.frag_size), width=24)
        self.frag_lbl.pack(side="left")
        self.frag_var.trace_add("write",
                                lambda *_: self.frag_lbl.configure(text=str(self.frag_var.get())))

        def chk(text: str, default: bool) -> tk.BooleanVar:
            var = tk.BooleanVar(value=default)
            ctk.CTkCheckBox(scroll, text=text, variable=var).pack(anchor="w", pady=2)
            return var

        self.sni_split_var = chk("Split TLS ClientHello inside SNI (рекомендуется)", self.cfg.split_at_sni)
        self.rec_split_var = chk("TLS record split — два валидных TLS-рекорда (рекомендуется)", self.cfg.tls_record_split)
        self.oob_var       = chk("Inject OOB byte между половинами (экспериментально)", self.cfg.oob_enabled)
        self.junk_var      = chk("Fake TLS record перед ClientHello (обычно ломает TLS)", self.cfg.junk_enabled)
        self.host_case_var = chk("Toggle HTTP Host header case", self.cfg.host_case_toggle)

        self.quic_var = tk.BooleanVar(value=quic_blocker.is_blocked())
        ctk.CTkCheckBox(scroll, text="Block QUIC (UDP 443) — нужен sudo/pkexec",
                        variable=self.quic_var).pack(anchor="w", pady=2)
        self.quic_var.trace_add("write", lambda *_: self._toggle_quic(self.quic_var.get()))

        ctk.CTkButton(scroll, text="Apply settings", command=self._apply_settings).pack(pady=10)

        ctk.CTkLabel(
            scroll,
            text=(
                "Браузер: SOCKS5 → 127.0.0.1:<port>\n"
                "Firefox: about:preferences → Параметры сети → SOCKS v5\n"
                "Включи «Proxy DNS when using SOCKS v5»"
            ),
            justify="left", text_color="gray", wraplength=460,
        ).pack(anchor="w", pady=6)

    # ── tray ──────────────────────────────────────────────────────────────────

    def _start_tray(self) -> None:
        try:
            import pystray
        except ImportError:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Show", lambda: self.after(0, self._show_window)),
            pystray.MenuItem("Quit",  lambda: self.after(0, self._quit)),
        )
        self._tray = pystray.Icon("dpibypass", _make_pil_icon("#cc4444"), "DPI Bypass", menu)
        threading.Thread(target=self._tray.run, daemon=True).start()

    def _show_window(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()

    def _on_close(self) -> None:
        if self._tray:
            self.withdraw()
        else:
            self._quit()

    # ── behaviour ─────────────────────────────────────────────────────────────

    def _toggle_proxy(self) -> None:
        if self.server.running:
            self.server.stop()
        else:
            self._apply_settings_silent()
            try:
                self.server.start()
            except OSError as e:
                self._on_log(f"[!] start failed: {e}")
        self._refresh_status()

    def _apply_settings(self) -> None:
        was_running = self.server.running
        if was_running:
            self.server.stop()
        self._apply_settings_silent()
        self._on_log(
            f"[cfg] port={self.cfg.port} frag={self.cfg.frag_size} "
            f"sni_split={self.cfg.split_at_sni} oob={self.cfg.oob_enabled} "
            f"junk={self.cfg.junk_enabled} host_case={self.cfg.host_case_toggle}"
        )
        if was_running:
            try:
                self.server.start()
            except OSError as e:
                self._on_log(f"[!] could not restart: {e}")

    def _apply_settings_silent(self) -> None:
        try:
            self.cfg.port = int(self.port_entry.get())
        except ValueError:
            pass
        self.cfg.frag_size      = int(self.frag_var.get())
        self.cfg.junk_enabled   = bool(self.junk_var.get())
        self.cfg.host_case_toggle = bool(self.host_case_var.get())
        self.cfg.split_at_sni   = bool(self.sni_split_var.get())
        self.cfg.tls_record_split = bool(self.rec_split_var.get())
        self.cfg.oob_enabled    = bool(self.oob_var.get())

    def _toggle_quic(self, checked: bool) -> None:
        ok, msg = quic_blocker.enable_block() if checked else quic_blocker.disable_block()
        self._on_log(f"[quic] {'on' if checked else 'off'}: {msg}")
        if not ok:
            self.quic_var.set(quic_blocker.is_blocked())

    def _reload_routing(self) -> None:
        domains = load_fragment_domains(_FRAG_FILE)
        self.cfg.fragment_domains = domains
        n = len(domains)
        self._on_log(f"[routing] {n} bypass domain{'s' if n != 1 else ''} loaded")
        self._refresh_status()

    def _refresh_status(self) -> None:
        running = self.server.running
        n = len(self.cfg.fragment_domains)
        self.domains_label.configure(
            text=f"bypass: {n} domain{'s' if n != 1 else ''}" if n else "bypass: ALL (no filter)"
        )
        if running:
            self.status_label.configure(text=f"Connected — 127.0.0.1:{self.cfg.port}")
            self.status_dot.configure(text_color="#44cc66")
            self.toggle_btn.configure(text="Stop", fg_color="#c0392b", hover_color="#922b21")
            self.conn_label.configure(text=f"{self.server.active_connections} connections")
            if self._tray:
                self._tray.icon = _make_pil_icon("#44cc66")
        else:
            self.status_label.configure(text="Disconnected")
            self.status_dot.configure(text_color="#cc4444")
            self.toggle_btn.configure(text="Start", fg_color=["#3a7ebf", "#1f538d"],
                                      hover_color=["#325882", "#14375e"])
            self.conn_label.configure(text="0 connections")
            if self._tray:
                self._tray.icon = _make_pil_icon("#cc4444")
        self.after(1000, self._refresh_status)

    # ── log ───────────────────────────────────────────────────────────────────

    def _on_log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_queue.put(f"[{ts}] {msg}")

    def _poll_log(self) -> None:
        try:
            while True:
                line = self._log_queue.get_nowait()
                self.log_view.configure(state="normal")
                self.log_view.insert("end", line + "\n")
                self.log_view.see("end")
                self.log_view.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(150, self._poll_log)

    def _quit(self) -> None:
        try:
            self.server.stop()
        except Exception:
            pass
        if self._tray:
            self._tray.stop()
        self.destroy()


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
