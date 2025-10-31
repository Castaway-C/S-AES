import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from utils.validators import validate_binary


class BasicTab:
    """基本加解密选项卡"""
    
    def __init__(self, parent, saes_interface, status_var):
        self.parent = parent
        self.saes_interface = saes_interface
        self.status_var = status_var
        
        self.frame = ttk.Frame(parent, padding="10")
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.frame, text="输入参数", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # 明文输入
        ttk.Label(input_frame, text="明/密文 (16位二进制):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.plaintext_entry = ttk.Entry(input_frame, width=30) # 适当加宽
        self.plaintext_entry.grid(row=0, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.plaintext_entry.insert(0, "0000000000000000")

        # 密钥输入
        ttk.Label(input_frame, text="密钥 (16位二进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=30) # 适当加宽
        self.key_entry.grid(row=1, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.key_entry.insert(0, "1010101010101010")

        # 按钮框架
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="加密",
                  command=self.encrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="解密",
                  command=self.decrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="清空",
                  command=self.clear_output).pack(side=tk.LEFT, padx=10)

        # 输出框架
        output_frame = ttk.LabelFrame(self.frame, text="输出结果", padding="10")
        output_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=70) # 增加高度
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置权重
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(2, weight=1) # 让输出框占满
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

    def encrypt(self):
        """基本加密"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(plaintext, 16):
                messagebox.showerror("错误", "明文必须是16位二进制数")
                return
            if not validate_binary(key, 16):
                messagebox.showerror("错误", "密钥必须是16位二进制数")
                return

            self.status_var.set("正在加密...")
            ciphertext = self.saes_interface.encrypt(plaintext, key)

            output_text = f"明文: {plaintext}\n密钥: {key}\n密文: {ciphertext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("加密完成")

        except Exception as e:
            messagebox.showerror("错误", f"加密过程中发生错误: {str(e)}")
            self.status_var.set("加密失败")

    def decrypt(self):
        """基本解密"""
        try:
            ciphertext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(ciphertext, 16):
                messagebox.showerror("错误", "密文必须是16位二进制数")
                return
            if not validate_binary(key, 16):
                messagebox.showerror("错误", "密钥必须是16位二进制数")
                return

            self.status_var.set("正在解密...")
            plaintext = self.saes_interface.decrypt(ciphertext, key)

            output_text = f"密文: {ciphertext}\n密钥: {key}\n明文: {plaintext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("解密完成")
            
        except Exception as e:
            messagebox.showerror("错误", f"解密过程中发生错误: {str(e)}")
            self.status_var.set("解密失败")

    def clear_output(self):
        """清空输出"""
        self.output_text.delete(1.0, tk.END)