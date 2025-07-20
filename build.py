import PyInstaller.__main__

PyInstaller.__main__.run([
    'smart.py',
    '--onefile',
    '--windowed',
    '--add-data=evidence:evidence',
    '--name=SmartSecuritySystem',
    '--hidden-import=pyaudio',
    '--hidden-import=librosa',
    '--hidden-import=numpy',
    '--hidden-import=cv2',
    '--hidden-import=PIL',
    '--hidden-import=PIL._tkinter_finder',  
    '--clean',
    '--log-level=INFO'
])
