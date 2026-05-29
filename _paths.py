import sys
from pathlib import Path


def bundle_root() -> Path:
    """Root where bundled read-only data lives (configs, probes).

    When frozen by PyInstaller, files are extracted to sys._MEIPASS.
    In dev mode, the project root (directory of this file) is used.
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent


def output_root() -> Path:
    """Root where writable output should be written (reports, logs).

    When frozen, write next to the .exe so the bundle's temp dir
    (sys._MEIPASS) is never used for output — it may be read-only.
    In dev mode, the project root is used.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent
