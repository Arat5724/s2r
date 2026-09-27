import sys
import tkinter as tk
from tkinter import filedialog

window = tk.Tk()
window.withdraw()
window.attributes('-topmost', True)
chosen = filedialog.askdirectory(title='S2R Review · 분석할 소스 프로젝트 폴더 선택', mustexist=True, parent=window)
window.destroy()
sys.stdout.buffer.write(chosen.encode('utf-8'))
