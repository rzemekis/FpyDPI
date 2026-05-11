"""Runtime hook: preload Tcl/Tk libs and fix library search path."""
import ctypes
import glob
import os
import sys

if getattr(sys, "frozen", False):
    _base = sys._MEIPASS

    # 1. Add _MEIPASS to LD_LIBRARY_PATH so dlopen() can find bundled .so files
    _old_lp = os.environ.get("LD_LIBRARY_PATH", "")
    os.environ["LD_LIBRARY_PATH"] = _base + (":" + _old_lp if _old_lp else "")

    # 2. Point TCL/TK to bundled init-script directories
    for _d in glob.glob(os.path.join(_base, "tcl*")):
        if os.path.isdir(_d):
            os.environ.setdefault("TCL_LIBRARY", _d)
    for _d in glob.glob(os.path.join(_base, "tk*")):
        if os.path.isdir(_d):
            os.environ.setdefault("TK_LIBRARY", _d)

    # 3. Force-load libtcl / libtk with RTLD_GLOBAL so their symbols are
    #    visible when _tkinter.so is subsequently loaded by the interpreter
    for _pat in ("libtcl*.so*", "libtk*.so*"):
        for _f in sorted(glob.glob(os.path.join(_base, _pat))):
            try:
                ctypes.CDLL(_f, mode=ctypes.RTLD_GLOBAL)
            except OSError:
                pass
