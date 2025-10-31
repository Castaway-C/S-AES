import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from utils.validators import validate_binary


class TripleEncryptionTab:
    """三重加密选项卡"""
    
    def __init__(self, parent, saes_interface, status_var):
        self.parent = parent
        self.saes_interface = saes_interface
        self.status_var = status_var
        
        self.frame = ttk.Frame(parent, padding="10")
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.frame, text="三重加密参数", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(input_frame, text="明/密文 (16位):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.plaintext_entry = ttk.Entry(input_frame, width=30)
        self.plaintext_entry.grid(row=0, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.plaintext_entry.insert(0, "0000000000000000")

        ttk.Label(input_frame, text="密钥 (48位二进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=50)
        self.key_entry.grid(row=1, column=1, pady=5, padx=(10, 0), sticky=(tk.W, tk.E))
        self.key_entry.insert(0, "101010101010101010101010101010101010101010101010")

        input_frame.columnconfigure(1, weight=1)

        # 按钮框架
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="三重加密",
                  command=self.triple_encrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="三重解密",
                  command=self.triple_decrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="清空",
                  command=self.clear_output).pack(side=tk.LEFT, padx=10)

        # 输出框架
        output_frame = ttk.LabelFrame(self.frame, text="三重加密输出", padding="10")
        output_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置权重
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(3, weight=1)

    def triple_encrypt(self):
        """三重加密"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(plaintext, 16):
                messagebox.showerror("错误", "明文必须是16位二进制数")
                return
            if not validate_binary(key, 48):
                messagebox.showerror("错误", "密钥必须是48位二进制数")
                return

            self.status_var.set("正在进行三重加密...")
            ciphertext = self.saes_interface.triple_encrypt(plaintext, key)

            output_text = f"明文: {plaintext}\n密钥: {key}\n三重加密密文: {ciphertext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("三重加密完成")

        except Exception as e:
            messagebox.showerror("错误", f"三重加密过程中发生错误: {str(e)}")
            self.status_var.set("三重加密失败")

    def triple_decrypt(self):
        """三重解密"""
        try:
            ciphertext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(ciphertext, 16):
                messagebox.showerror("错误", "密文必须是16位二进制数")
                return
            if not validate_binary(key, 48):
                messagebox.showerror("错误", "密钥必须是48位二进制数")
                return

            self.status_var.set("正在进行三重解密...")
            plaintext = self.saes_interface.triple_decrypt(ciphertext, key)

            output_text = f"密文: {ciphertext}\n密钥: {key}\n三重解密明文: {plaintext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("三重解密完成")
            
        except Exception as e:
            messagebox.showerror("错误", f"三重解密过程中发生错误: {str(e)}")
            self.status_var.set("三重解密失败")

    def clear_output(self):
        """清空输出"""
        self.output_text.delete(1.0, tk.END)