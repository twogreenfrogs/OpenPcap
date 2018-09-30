# -*- mode: python -*-

block_cipher = None
# from CLI, run 'pyinstaller --onefile OpenPcap.spec'

a = Analysis(['OpenPcapGUI.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
		  Tree('.\\resources', prefix='resources\\'),
          a.zipfiles,
          a.datas,
          name='OpenPcap',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False , icon='resources\\logo.ico')
