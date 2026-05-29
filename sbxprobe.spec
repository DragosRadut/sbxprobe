# sbxprobe.spec — PyInstaller one-file bundle
#
# Build with:
#   pip install pyinstaller
#   pyinstaller sbxprobe.spec
#
# The resulting sbxprobe.exe is in dist/.
# UPX compression is disabled intentionally — compressed PE sections can
# trigger AV heuristics which would defeat the purpose of sandbox testing.

block_cipher = None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[
        # Bundle the YAML configs so they're accessible via bundle_root()
        ("configs", "configs"),
        # Bundle the probe binaries so they're accessible via bundle_root()
        ("probes",  "probes"),
    ],
    hiddenimports=[
        # PyInstaller can miss these because they're imported by string or
        # are local packages that share names with stdlib modules.
        "_paths",
        "config_loader",
        "runner",
        "runner.executor",
        "runner.adapters",
        "runner.adapters.alkhaser",
        "runner.adapters.pafish",
        "parser",
        "parser.normalizer",
        "parser.pafish_normalizer",
        "scoring",
        "scoring.engine",
        "reporting",
        "reporting.generator",
        "reporting.html_generator",
        "reporting.combined_html",
        "yaml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Keep the bundle small — none of these are used.
        "tkinter",
        "unittest",
        "email",
        "http",
        "xml",
        "xmlrpc",
        "pydoc",
        "doctest",
        "difflib",
        "ftplib",
        "getpass",
        "imaplib",
        "logging",
        "multiprocessing",
        "sqlite3",
        "ssl",
        "urllib",
    ],
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
    name="sbxprobe",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,       # disabled — UPX can trigger AV false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,    # keep console; sbxprobe prints progress to stdout
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
