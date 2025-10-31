import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from utils.validators import validate_binary


class CBCTab:
    """CBC模式选项卡"""
    
    def __init__(self, parent, saes_interface, status_var):
        self.parent = parent
        self.saes_interface = saes_interface
        self.status_var = status_var
        
        self.frame = ttk.Frame(parent, padding="10")
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.frame, text="CBC模式参数", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(input_frame, text="长明/密文:").grid(row=0, column=0, sticky=tk.NW, pady=5)
        self.plaintext_entry = scrolledtext.ScrolledText(input_frame, height=5, width=60)
        self.plaintext_entry.grid(row=0, column=1, pady=5, padx=(10, 0), sticky=(tk.W, tk.E))
        self.plaintext_entry.insert("1.0", "This is a long message for CBC mode testing.")

        ttk.Label(input_frame, text="密钥 (16位二进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=30)
        self.key_entry.grid(row=1, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.key_entry.insert(0, "1010101010101010")

        ttk.Label(input_frame, text="初始向量IV (16位):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.iv_entry = ttk.Entry(input_frame, width=30)
        self.iv_entry.grid(row=2, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.iv_entry.insert(0, "1100110011001100")

        input_frame.columnconfigure(1, weight=1) # 让文本框可拉伸

        # 按钮框架
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="CBC加密",
                  command=self.cbc_encrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="CBC解密",
                  command=self.cbc_decrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="篡改测试",
                  command=self.cbc_tamper_test).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="清空",
                  command=self.clear_output).pack(side=tk.LEFT, padx=10)

        # 输出框架
        output_frame = ttk.LabelFrame(self.frame, text="CBC模式输出", padding="10")
        output_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置权重
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(2, weight=1)

    def cbc_encrypt(self):
        """CBC模式加密"""
        try:
            plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            iv = self.iv_entry.get().strip()

            if not plaintext:
                messagebox.showerror("错误", "请输入要加密的明文")
                return
            if not validate_binary(key, 16):
                messagebox.showerror("错误", "密钥必须是16位二进制数")
                return
            if not validate_binary(iv, 16):
                messagebox.showerror("错误", "初始向量必须是16位二进制数")
                return

            self.status_var.set("正在进行CBC模式加密...")
            ciphertext = self.saes_interface.cbc_encrypt(plaintext, key, iv)

            output_text = (f"明文: {plaintext}\n密钥: {key}\n初始向量: {iv}\n"
                           f"CBC加密结果 (原始): {ciphertext}\n"
                           f"CBC加密结果 (Hex): {ciphertext.encode('utf-8', 'ignore').hex()}\n")
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("CBC加密完成")

        except Exception as e:
            messagebox.showerror("错误", f"CBC加密过程中发生错误: {str(e)}")
            self.status_var.set("CBC加密失败")

    def cbc_decrypt(self):
        """CBC模式解密"""
        try:
            ciphertext = self.plaintext_entry.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            iv = self.iv_entry.get().strip()

            if not ciphertext:
                messagebox.showerror("错误", "请输入要解密的密文")
                return
            if not validate_binary(key, 16):
                messagebox.showerror("错误", "密钥必须是16位二进制数")
                return
            if not validate_binary(iv, 16):
                messagebox.showerror("错误", "初始向量必须是16位二进制数")
                return

            self.status_var.set("正在进行CBC模式解密...")
            plaintext = self.saes_interface.cbc_decrypt(ciphertext, key, iv)

            output_text = f"密文: {ciphertext}\n密钥: {key}\n初始向量: {iv}\nCBC解密结果: {plaintext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("CBC解密完成")

        except Exception as e:
            messagebox.showerror("错误", f"CBC解密过程中发生错误: {str(e)}")
            self.status_var.set("CBC解密失败")

    def cbc_tamper_test(self):
        """CBC篡改测试"""
        try:
            plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            iv = self.iv_entry.get().strip()

            if not plaintext:
                messagebox.showerror("错误", "请输入要测试的明文")
                return
            if not validate_binary(key, 16):
                messagebox.showerror("错误", "密钥必须是16位二进制数")
                return
            if not validate_binary(iv, 16):
                messagebox.showerror("错误", "初始向量必须是16位二进制数")
                return

            self.status_var.set("正在进行CBC篡改测试...")
            result = self.saes_interface.cbc_tamper_test(plaintext, key, iv)

            output_text = (f"--- CBC篡改测试开始 ---\n"
                           f"原始明文: {plaintext}\n密钥: {key}\n初始向量: {iv}\n\n"
                           f"{result}\n"
                           f"--- CBC篡改测试结束 ---\n")

            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("CBC篡改测试完成")
            
        except Exception as e:
            messagebox.showerror("错误", f"CBC篡改测试过程中发生错误: {str(e)}")
            self.status_var.set("CBC篡改测试失败")

    def clear_output(self):
        """清空输出"""
        self.output_text.delete(1.0, tk.END)