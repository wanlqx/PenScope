# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('frontend', 'frontend'), ('assets', 'assets'), ('config/dicts', 'config/dicts')]
binaries = []
hiddenimports = ['scanner', 'scanner.payloads', 'scanner.port_scan', 'scanner.web_scan', 'scanner.cmd_injection', 'scanner.api_scan', 'scanner.subdomain', 'scanner.contentscan', 'scanner.mail_probe', 'scanner.traversal', 'scanner.ssrf', 'scanner.access_control', 'scanner.auth', 'scanner.open_redirect', 'scanner.scope', 'scanner.vuln_db', 'scanner.cred_dict', 'scanner.vault', 'scanner.session_renew', 'app_api', 'reports', 'db', 'run_scans', 'config', 'cvss_dedup', 'requests', 'webview', 'pystray', 'pystray._win32', 'PIL', 'asset_watch', 'notify', 'topology']
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PenScope',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['PenScope.exe'],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\icon.ico'],
)
