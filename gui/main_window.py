import tkinter as tk
from tkinter import ttk

from .styles import setup_styles
from .tabs import (
    BasicTab,
    AsciiTab,
    DoubleEncryptionTab,
    TripleEncryptionTab,
    CBCTab
)


class SAESGUI:
    """S-AES加密解密主界面"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密解密工具")
        self.root.geometry("850x700")
        self.root.minsize(700, 600)

        # 设置样式
        setup_styles()

        # 初始化算法接口
        from core.saes_interface import SAESInterface
        self.saes_interface = SAESInterface()

        # 创建界面
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 标题
        title_label = ttk.Label(main_frame, text="S-AES加密解密系统", style='Title.TLabel', anchor="center")
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=(tk.W, tk.E))

        # 状态栏变量
        self.status_var = tk.StringVar(value="就绪")

        # 创建选项卡
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        # 创建各个功能页面
        self.create_tabs()

        # 状态栏
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style='Status.TLabel', anchor=tk.W)
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        # 配置权重
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1) # 选项卡区域占满
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
    def create_tabs(self):
        """创建所有选项卡"""
        # 基本加解密
        self.basic_tab = BasicTab(self.notebook, self.saes_interface, self.status_var)
        self.notebook.add(self.basic_tab.frame, text="基本加解密")
        
        # ASCII加解密
        self.ascii_tab = AsciiTab(self.notebook, self.saes_interface, self.status_var)
        self.notebook.add(self.ascii_tab.frame, text="ASCII加解密")
        
        # 双重加密
        self.double_tab = DoubleEncryptionTab(self.notebook, self.saes_interface, self.status_var)
        self.notebook.add(self.double_tab.frame, text="双重加密")
        
        # 三重加密
        self.triple_tab = TripleEncryptionTab(self.notebook, self.saes_interface, self.status_var)
        self.notebook.add(self.triple_tab.frame, text="三重加密")
        
        # CBC模式
        self.cbc_tab = CBCTab(self.notebook, self.saes_interface, self.status_var)
        self.notebook.add(self.cbc_tab.frame, text="CBC模式")