"""DPI Bypass SOCKS5 Proxy GUI (PyQt6)."""

from __future__ import annotations

import os
import sys
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QGuiApplication, QIcon, QPixmap, QPainter, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSlider,
    QSpinBox,
    QSystemTrayIcon,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

import quic_blocker
from proxy import ProxyConfig, SocksProxyServer
from vless_router import load_fragment_domains

_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)
_FRAG_FILE = os.path.join(_DIR, "fragmentthis.txt")


def _make_icon(color: str) -> QIcon:
    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(8, 8, 48, 48)
    p.end()
    return QIcon(pix)


class MainWindow(QMainWindow):
    log_signal = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DPI Bypass — SOCKS5")
        self.resize(720, 520)

        domains = load_fragment_domains(_FRAG_FILE)
        self.cfg = ProxyConfig(
            log_callback=self._on_log,
            fragment_domains=domains,
        )
        self.server = SocksProxyServer(self.cfg)
        self.log_signal.connect(self._append_log)

        self._build_ui()
        self._build_tray()

        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_status)
        self._status_timer.start(1000)

    # ---- UI ----------------------------------------------------------
    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._build_dashboard(), "Dashboard")
        tabs.addTab(self._build_settings(), "Settings")
        self.setCentralWidget(tabs)

    def _build_dashboard(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("font-size: 18px; font-weight: 600;")
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet("color: #cc4444; font-size: 22px;")

        status_row = QHBoxLayout()
        status_row.addWidget(self.status_dot)
        status_row.addWidget(self.status_label)
        status_row.addStretch(1)
        self.conn_label = QLabel("0 connections")
        self.conn_label.setStyleSheet("color: #888;")
        status_row.addWidget(self.conn_label)
        layout.addLayout(status_row)

        self.toggle_btn = QPushButton("Start")
        self.toggle_btn.setMinimumHeight(56)
        self.toggle_btn.setStyleSheet("font-size: 18px; font-weight: 600;")
        self.toggle_btn.clicked.connect(self._toggle_proxy)
        layout.addWidget(self.toggle_btn)

        routing_row = QHBoxLayout()
        self.domains_label = QLabel("bypass: — domains")
        self.domains_label.setStyleSheet("color: #888; font-size: 12px;")
        reload_btn = QPushButton("↺ Reload routing")
        reload_btn.setMaximumHeight(28)
        reload_btn.setToolTip("Reload fragmentthis.txt")
        reload_btn.clicked.connect(self._reload_routing)
        routing_row.addWidget(self.domains_label)
        routing_row.addStretch(1)
        routing_row.addWidget(reload_btn)
        layout.addLayout(routing_row)

        layout.addWidget(QLabel("Log:"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view, stretch=1)
        return w

    def _build_settings(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(self.cfg.port)
        form.addRow("Proxy port:", self.port_spin)

        self.frag_slider = QSlider(Qt.Orientation.Horizontal)
        self.frag_slider.setRange(1, 10)
        self.frag_slider.setValue(self.cfg.frag_size)
        self.frag_value = QLabel(str(self.cfg.frag_size))
        self.frag_slider.valueChanged.connect(lambda v: self.frag_value.setText(str(v)))
        frag_row = QHBoxLayout()
        frag_row.addWidget(self.frag_slider, stretch=1)
        frag_row.addWidget(self.frag_value)
        frag_wrap = QWidget(); frag_wrap.setLayout(frag_row)
        form.addRow("Fragment size (bytes):", frag_wrap)

        self.sni_split_cb = QCheckBox("Split TLS ClientHello inside SNI (recommended)")
        self.sni_split_cb.setChecked(self.cfg.split_at_sni)
        form.addRow(self.sni_split_cb)

        self.rec_split_cb = QCheckBox("Use TLS record split — two valid TLS records (recommended for YouTube/TSPU)")
        self.rec_split_cb.setChecked(self.cfg.tls_record_split)
        form.addRow(self.rec_split_cb)

        self.oob_cb = QCheckBox("Inject OOB byte between halves (some DPIs RST on this)")
        self.oob_cb.setChecked(self.cfg.oob_enabled)
        form.addRow(self.oob_cb)

        self.junk_cb = QCheckBox("Prepend fake TLS record (experimental — usually breaks TLS)")
        self.junk_cb.setChecked(self.cfg.junk_enabled)
        form.addRow(self.junk_cb)

        self.host_case_cb = QCheckBox("Toggle HTTP Host header case")
        self.host_case_cb.setChecked(self.cfg.host_case_toggle)
        form.addRow(self.host_case_cb)

        self.quic_cb = QCheckBox("Block QUIC (UDP 443) — REQUIRED for YouTube videos; needs pkexec/sudo")
        self.quic_cb.setChecked(quic_blocker.is_blocked())
        self.quic_cb.toggled.connect(self._toggle_quic)
        form.addRow(self.quic_cb)

        apply_btn = QPushButton("Apply settings")
        apply_btn.clicked.connect(self._apply_settings)
        form.addRow(apply_btn)

        info = QLabel(
            "Configure your browser to use SOCKS5 at 127.0.0.1:&lt;port&gt;.\n"
            "Firefox: Preferences → Network Settings → Manual proxy → SOCKS v5,\n"
            "tick \"Proxy DNS when using SOCKS v5\"."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #888;")
        form.addRow(info)
        return w

    def _build_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        self.tray = QSystemTrayIcon(_make_icon("#cc4444"), self)
        self.tray.setToolTip("DPI Bypass (stopped)")
        menu = QMenu()
        self.tray_toggle = QAction("Start", self)
        self.tray_toggle.triggered.connect(self._toggle_proxy)
        menu.addAction(self.tray_toggle)
        show_act = QAction("Show window", self)
        show_act.triggered.connect(self._show_from_tray)
        menu.addAction(show_act)
        quit_act = QAction("Quit", self)
        quit_act.triggered.connect(self._quit)
        menu.addAction(quit_act)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    # ---- behaviour ---------------------------------------------------
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

    def _apply_settings_silent(self) -> None:
        self.cfg.port = self.port_spin.value()
        self.cfg.frag_size = self.frag_slider.value()
        self.cfg.junk_enabled = self.junk_cb.isChecked()
        self.cfg.host_case_toggle = self.host_case_cb.isChecked()
        self.cfg.split_at_sni = self.sni_split_cb.isChecked()
        self.cfg.tls_record_split = self.rec_split_cb.isChecked()
        self.cfg.oob_enabled = self.oob_cb.isChecked()

    def _toggle_quic(self, checked: bool) -> None:
        if checked:
            ok, msg = quic_blocker.enable_block()
        else:
            ok, msg = quic_blocker.disable_block()
        self._on_log(f"[quic] {'on' if checked else 'off'}: {msg}")
        if not ok:
            self.quic_cb.blockSignals(True)
            self.quic_cb.setChecked(quic_blocker.is_blocked())
            self.quic_cb.blockSignals(False)

    def _reload_routing(self) -> None:
        domains = load_fragment_domains(_FRAG_FILE)
        self.cfg.fragment_domains = domains
        n = len(domains)
        self._on_log(f"[routing] {n} bypass domain{'s' if n != 1 else ''} loaded")
        self._refresh_status()

    def _refresh_status(self) -> None:
        running = self.server.running
        n = len(self.cfg.fragment_domains)
        self.domains_label.setText(
            f"bypass: {n} domain{'s' if n != 1 else ''}" if n else "bypass: ALL (no filter)"
        )
        if running:
            self.status_label.setText(f"Connected — 127.0.0.1:{self.cfg.port}")
            self.status_dot.setStyleSheet("color: #44cc66; font-size: 22px;")
            self.toggle_btn.setText("Stop")
            self.conn_label.setText(f"{self.server.active_connections} connections")
            if self.tray:
                self.tray.setIcon(_make_icon("#44cc66"))
                self.tray.setToolTip(f"DPI Bypass running on 127.0.0.1:{self.cfg.port}")
                self.tray_toggle.setText("Stop")
        else:
            self.status_label.setText("Disconnected")
            self.status_dot.setStyleSheet("color: #cc4444; font-size: 22px;")
            self.toggle_btn.setText("Start")
            self.conn_label.setText("0 connections")
            if self.tray:
                self.tray.setIcon(_make_icon("#cc4444"))
                self.tray.setToolTip("DPI Bypass (stopped)")
                self.tray_toggle.setText("Start")

    # ---- log plumbing ------------------------------------------------
    def _on_log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_signal.emit(f"[{ts}] {msg}")

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    # ---- tray helpers ------------------------------------------------
    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show_from_tray()

    def _show_from_tray(self) -> None:
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt API)
        if self.tray and self.tray.isVisible():
            self.hide()
            event.ignore()
            return
        self._quit()

    def _quit(self) -> None:
        try:
            self.server.stop()
        except Exception:
            pass
        QApplication.quit()


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    QGuiApplication.setApplicationDisplayName("DPI Bypass")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
