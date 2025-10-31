import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from utils.validators import validate_binary


class DoubleEncryptionTab:
    """双重加密选项卡"""
    
    def __init__(self, parent, saes_interface, status_var):
        self.parent = parent
        self.saes_interface = saes_interface
        self.status_var = status_var
        
        self.frame = ttk.Frame(parent, padding="10")
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.frame, text="双重加密参数", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(input_frame, text="明/密文 (16位):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.plaintext_entry = ttk.Entry(input_frame, width=30)
        self.plaintext_entry.grid(row=0, column=1, pady=5, padx=(10, 0), sticky=tk.W)
        self.plaintext_entry.insert(0, "0000000000000000")

        ttk.Label(input_frame, text="密钥 (32位二进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=40)
        self.key_entry.grid(row=1, column=1, pady=5, padx=(10, 0), sticky=(tk.W, tk.E))
        self.key_entry.insert(0, "10101010101010101010101010101010")

        input_frame.columnconfigure(1, weight=1)

        # 中间相遇攻击部分
        attack_frame = ttk.LabelFrame(self.frame, text="中间相遇攻击", padding="10")
        attack_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(attack_frame, text="已知明文 (16位):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.known_plaintext_entry = ttk.Entry(attack_frame, width=30)
        self.known_plaintext_entry.grid(row=0, column=1, pady=2, padx=(10, 0), sticky=tk.W)
        self.known_plaintext_entry.insert(0, "0000000000000000")

        ttk.Label(attack_frame, text="已知密文 (16位):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.known_ciphertext_entry = ttk.Entry(attack_frame, width=30)
        self.known_ciphertext_entry.grid(row=1, column=1, pady=2, padx=(10, 0), sticky=tk.W)
        self.known_ciphertext_entry.insert(0, "1000000100000001") # 示例密文

        # 按钮框架
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="双重加密",
                  command=self.double_encrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="双重解密",
                  command=self.double_decrypt).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="中间相遇攻击",
                  command=self.meet_in_middle_attack).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="清空",
                  command=self.clear_output).pack(side=tk.LEFT, padx=10)

        # 输出框架
        output_frame = ttk.LabelFrame(self.frame, text="双重加密输出", padding="10")
        output_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # 配置权重
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(4, weight=1)

    def double_encrypt(self):
        """双重加密"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(plaintext, 16):
                messagebox.showerror("错误", "明文必须是16位二进制数")
                return
            if not validate_binary(key, 32):
                messagebox.showerror("错误", "密钥必须是32位二进制数")
                return

            self.status_var.set("正在进行双重加密...")
            ciphertext = self.saes_interface.double_encrypt(plaintext, key)

            output_text = f"明文: {plaintext}\n密钥: {key}\n双重加密密文: {ciphertext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("双重加密完成")

        except Exception as e:
            messagebox.showerror("错误", f"双重加密过程中发生错误: {str(e)}")
            self.status_var.set("双重加密失败")

    def double_decrypt(self):
        """双重解密"""
        try:
            ciphertext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            if not validate_binary(ciphertext, 16):
                messagebox.showerror("错误", "密文必须是16位二进制数")
                return
            if not validate_binary(key, 32):
                messagebox.showerror("错误", "密钥必须是32位二进制数")
                return

            self.status_var.set("正在进行双重解密...")
            plaintext = self.saes_interface.double_decrypt(ciphertext, key)

            output_text = f"密文: {ciphertext}\n密钥: {key}\n双重解密明文: {plaintext}\n"
            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set("双重解密完成")

        except Exception as e:
            messagebox.showerror("错误", f"双重解密过程中发生错误: {str(e)}")
            self.status_var.set("双重解密失败")

    def meet_in_middle_attack(self):
        """中间相遇攻击"""
        try:
            plaintext = self.known_plaintext_entry.get().strip()
            ciphertext = self.known_ciphertext_entry.get().strip()

            if not validate_binary(plaintext, 16):
                messagebox.showerror("错误", "已知明文必须是16位二进制数")
                return
            if not validate_binary(ciphertext, 16):
                messagebox.showerror("错误", "已知密文必须是16位二进制数")
                return

            self.status_var.set("正在进行中间相遇攻击...")
            self.frame.update_idletasks() # 强制更新UI显示状态

            found_keys = self.saes_interface.meet_in_middle_attack(plaintext, ciphertext)

            output_text = f"--- 中间相遇攻击开始 ---\n"
            output_text += f"已知明文: {plaintext}\n已知密文: {ciphertext}\n"
            if found_keys:
                output_text += f"找到 {len(found_keys)} 个匹配的密钥对 (K1, K2):\n"
                for (k1, k2) in found_keys:
                    output_text += f"  K1: {k1}, K2: {k2} (完整密钥: {k1+k2})\n"
            else:
                output_text += "未找到匹配的密钥对\n"

            self.output_text.insert(tk.END, output_text + "-"*60 + "\n")
            self.output_text.see(tk.END)
            self.status_var.set(f"中间相遇攻击完成，找到 {len(found_keys)} 个密钥对")
            
        except Exception as e:
            messagebox.showerror("错误", f"中间相遇攻击过程中发生错误: {str(e)}")
            self.status_var.set("中间相遇攻击失败")

    def clear_output(self):
        """清空输出"""
        self.output_text.delete(1.0, tk.END)