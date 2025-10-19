# -*- mode: python ; coding: utf-8 -*-
import os
import pathlib

block_cipher = None

project_root = pathlib.Path(__file__).resolve().parent.parent
assets = [
    (project_root / 'assets' / 'logo.svg', 'assets'),
    (project_root / 'assets' / 'starfield.svg', 'assets'),
    (project_root / 'data' / 'mock_processes.json', 'data'),
]

added_datas = [(str(src), dest) for src, dest in assets]

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=added_datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
version_file = os.environ.get('WHOIS_WATCHING_VERSION_FILE')

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='WHOIS_Watching',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=version_file,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='WHOIS_Watching',
)
