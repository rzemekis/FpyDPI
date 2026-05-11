# -*- mode: python ; coding: utf-8 -*-
import glob
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ctk_datas  = collect_data_files('customtkinter')
ctk_hidden = collect_submodules('customtkinter')

# ── Bundle Tcl/Tk shared libs and init scripts (Linux) ───────────────────────
import subprocess
import sysconfig

def _tcltk_bins():
    """Use ldd on _tkinter.so to find exact libtcl/libtk paths."""
    ext = sysconfig.get_config_var('EXT_SUFFIX') or '.so'
    stdlib = sysconfig.get_path('stdlib')
    tkmod = os.path.join(stdlib, 'lib-dynload', f'_tkinter{ext}')
    if not os.path.exists(tkmod):
        print(f'[spec] WARNING: _tkinter not found at {tkmod}')
        return []
    try:
        out = subprocess.check_output(['ldd', tkmod], text=True)
    except Exception as e:
        print(f'[spec] WARNING: ldd failed: {e}')
        return []
    result = []
    for line in out.splitlines():
        if 'libtcl' in line or 'libtk' in line:
            if '=>' in line:
                path = line.split('=>')[1].strip().split()[0]
                if os.path.exists(path):
                    result.append((path, '.'))
                    print(f'[spec] bundling {path}')
    return result

def _tcltk_datas():
    result = []
    for pat in (
        '/usr/lib/tcl*', '/usr/lib/tk*',
        '/usr/share/tcl*', '/usr/share/tk*',
        '/usr/lib64/tcl*', '/usr/lib64/tk*',
    ):
        for d in glob.glob(pat):
            if os.path.isdir(d) and any(
                os.path.exists(os.path.join(d, f)) for f in ('init.tcl', 'tk.tcl')
            ):
                result.append((d, os.path.basename(d)))
                print(f'[spec] bundling data dir {d}')
    return result
# ─────────────────────────────────────────────────────────────────────────────

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=_tcltk_bins(),
    datas=ctk_datas + _tcltk_datas(),
    hiddenimports=ctk_hidden + ['_tkinter', 'PIL._imagingtk', 'pystray'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['_tcl_hook.py'],
    excludes=['PyQt6', 'PyQt5', 'PySide2', 'PySide6'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='dpibypass',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
