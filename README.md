# S-AES 简化AES加密算法工具

## 1. 项目简介

本项目为《信息安全导论》课程作业（作业2），使用 **Python** 和 **Tkinter** 图形库实现了一个完整的 **S-AES** (简化AES) 算法加密工具。

该工具提供了一个用户友好的多标签图形界面，严格遵循《密码编码学与网络安全》附录D的S-AES标准，实现了S-AES的作业要求：包括基础加解密、ASCII字符串处理、双重加密、三重加密、中间相遇攻击以及CBC工作模式。

## 2. 主要功能

本工具通过一个包含五个选项卡的界面，清晰地划分了作业要求的各项功能：

#### 2.1 基础加解密 (关卡1)
- **输入**: 16位二进制明文/密文 和 16位二进制密钥。
- **功能**: 对输入的数据执行标准的S-AES加密或解密操作。
- **输出**: 16位二进制结果。
<img width="1278" height="942" alt="11" src="https://github.com/user-attachments/assets/69397633-c88b-4d1c-950c-7df1e8c049ed" />

#### 2.2 ASCII字符串处理 (关卡3)
- **输入**: 任意长度的ASCII字符串 和 16位二进制密钥。
- **功能**: 将输入字符串按2字节 (16位) 分组，每个分组作为独立的S-AES分组进行加密或解密。
- **输出**: 对应的加密/解密后字符串（可能为乱码）。
<img width="1275" height="961" alt="31" src="https://github.com/user-attachments/assets/33243ca2-0a2d-406c-8a6f-3be4aa55f5ca" />

#### 2.3 双重加密与攻击 (关卡4)
- **双重加密**:
    - **输入**: 16位明/密文 和 32位二进制密钥 (K1+K2)。
    - **功能**: 执行 `C = E(K2, E(K1, P))` 的双重加密，或反向解密。
    - <img width="1275" height="1056" alt="41" src="https://github.com/user-attachments/assets/68154ac4-bd7b-4312-9611-54927e94b09b" />

- **中间相遇攻击**:
    - **输入**: 一对已知的明文和密文（16位二进制）。
    - **功能**: 遍历 $2^{16}$ 个K1和 $2^{16}$ 个K2，通过查找 `E(K1, P) == D(K2, C)` 来找出所有可能的32位密钥。
<img width="1275" height="1056" alt="41" src="https://github.com/user-attachments/assets/add913c8-2988-42b7-a6b0-d28a2ce62f5c" />

#### 2.4 三重加密 (关卡4)
- **输入**: 16位明/密文 和 48位二进制密钥 (K1+K2+K3)。
- **功能**: 按照 E-D-E (加密-解密-加密) 模式执行三重S-AES加解密操作。
<img width="1269" height="946" alt="43" src="https://github.com/user-attachments/assets/00e88838-6d06-4028-8951-08ad2de47265" />

#### 2.5 CBC工作模式 (关卡5)
- **输入**: 任意长度的ASCII明/密文、16位密钥 和 16位初始向量(IV)。
- **功能**: 基于S-AES算法，使用密码分组链 (CBC) 模式对较长的明文消息进行加密和解密。
- **篡改测试**: 提供一个按钮来自动执行密文篡改（修改一个密文分组），并对比解密结果，以展示CBC模式的错误传播特性。
<img width="1271" height="1067" alt="51" src="https://github.com/user-attachments/assets/0ebdc940-2686-4e41-a49b-b6593a00b607" />
<img width="1273" height="1221" alt="52" src="https://github.com/user-attachments/assets/5a8a0463-afb2-4d4f-a883-54e64dbe88bf" />

## 3. 技术栈

- **编程语言**: Python 3
- **图形库**: Tkinter (ttk, ttkthemes)

## 4. 项目核心文件结构

```
.
├── main.py                 # GUI程序的主入口
├── core/
│   ├── saes_core.py        # S-AES算法核心实现 
│   └── saes_interface.py   # 连接GUI与核心的算法逻辑接口
├── gui/
│   ├── main_window.py      # Tkinter主窗口和选项卡布局
│   ├── styles.py           # GUI样式配置
│   └── tabs/               # 存放各个功能选项卡的UI代码
│       ├── basic_tab.py    # -- 基础加解密 
│       ├── ascii_tab.py    # -- ASCII加解密
│       ├── double_tab.py   # -- 双重加密与中间相遇攻击
│       ├── triple_tab.py   # -- 三重加密
│       └── cbc_tab.py      # -- CBC模式
└── utils/
    └── validators.py       # 输入验证工具函数 
```
