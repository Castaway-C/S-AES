class SAESCore:
    """
    S-AES核心算法类
    """
    
    # S盒
    S_BOX = [
        [0x9, 0x4, 0xA, 0xB],
        [0xD, 0x1, 0x8, 0x5],
        [0x6, 0x2, 0x0, 0x3],
        [0xC, 0xE, 0xF, 0x7]
    ]
    
    # 逆S盒
    INV_S_BOX = [
        [0xA, 0x5, 0x9, 0xB],
        [0x1, 0x7, 0x8, 0xF],
        [0x6, 0x0, 0x2, 0x3],
        [0xC, 0x4, 0xD, 0xE]
    ]
    
    # GF(2^4)乘法表
    GF_MULT_TABLE = {
        0x1: [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
        0x2: [0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD],
        0x4: [0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9],
        0x9: [0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE]
    }
    
    # 轮常数
    RCON = [0x80, 0x30]  # RCON(1)=10000000, RCON(2)=00110000
    
    @staticmethod
    def text_to_binary(text: str) -> str:
        """将文本转换为二进制字符串"""
        binary = ''
        for char in text:
            binary += format(ord(char), '08b')
        return binary
    
    @staticmethod
    def binary_to_text(binary: str) -> str:
        """将二进制字符串转换为文本"""
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                text += chr(int(byte, 2))
        return text
    
    @staticmethod
    def xor_binary(a: str, b: str) -> str:
        """二进制字符串异或运算"""
        result = ''
        for i in range(len(a)):
            result += '1' if a[i] != b[i] else '0'
        return result
    
    @staticmethod
    def split_16bit(data: str) -> tuple:
        """将16位数据分割为两个8位字"""
        if len(data) != 16:
            raise ValueError("数据必须是16位")
        return data[:8], data[8:]
    
    @staticmethod
    def combine_8bit(w0: str, w1: str) -> str:
        """将两个8位字组合为16位数据"""
        if len(w0) != 8 or len(w1) != 8:
            raise ValueError("输入必须是8位")
        return w0 + w1
    
    @staticmethod
    def nibble_substitution(nibble: str, inverse: bool = False) -> str:
        """
        半字节代替
        """
        if len(nibble) != 4:
            raise ValueError("半字节必须是4位")
        
        # 转换为整数
        val = int(nibble, 2)
        row = (val >> 2) & 0x3
        col = val & 0x3
        
        # 选择S盒
        s_box = SAESCore.INV_S_BOX if inverse else SAESCore.S_BOX
        
        # 查找替换值
        substituted = s_box[row][col]
        
        # 转换回4位二进制
        return format(substituted, '04b')
    
    @staticmethod
    def shift_rows(state: list) -> list:
        """
        行移位
        """
        # 第二行循环左移1个半字节
        return [
            [state[0][0], state[0][1]],
            [state[1][1], state[1][0]]  # 交换s10和s11
        ]
    
    @staticmethod
    def inv_shift_rows(state: list) -> list:
        """
        逆行移位
        """
        # 逆行移位与行移位相同
        return SAESCore.shift_rows(state)
    
    @staticmethod
    def gf_multiply(a: int, b: int) -> int:
        """
        GF(2^4)乘法
        """
        if a == 0 or b == 0:
            return 0
        
        # 使用预计算的乘法表
        if a in SAESCore.GF_MULT_TABLE:
            return SAESCore.GF_MULT_TABLE[a][b]
        elif b in SAESCore.GF_MULT_TABLE:
            return SAESCore.GF_MULT_TABLE[b][a]
        else:
            # 直接计算
            result = 0
            for i in range(4):
                if (b >> i) & 1:
                    result ^= (a << i)
            
            # 模 x^4 + x + 1 (0x13)
            if result >= 16:
                result %= 0x13
            
            return result
    
    @staticmethod
    def mix_columns(state: list, inverse: bool = False) -> list:
        """
        列混淆
        """
        if inverse:
            # 逆列混淆矩阵 [[9, 2], [2, 9]]
            matrix = [[0x9, 0x2], [0x2, 0x9]]
        else:
            # 列混淆矩阵 [[1, 4], [4, 1]]
            matrix = [[0x1, 0x4], [0x4, 0x1]]
        
        new_state = [[0, 0], [0, 0]]
        
        for i in range(2):
            for j in range(2):
                # 将半字节转换为整数
                s0j = int(state[0][j], 2) if isinstance(state[0][j], str) else state[0][j]
                s1j = int(state[1][j], 2) if isinstance(state[1][j], str) else state[1][j]
                
                # 矩阵乘法
                result = (SAESCore.gf_multiply(matrix[i][0], s0j) ^ 
                         SAESCore.gf_multiply(matrix[i][1], s1j))
                
                # 转换回二进制字符串
                new_state[i][j] = format(result, '04b')
        
        return new_state
    
    @staticmethod
    def add_round_key(state: list, round_key: list) -> list:
        """
        轮密钥加
        """
        new_state = [[0, 0], [0, 0]]
        
        for i in range(2):
            for j in range(2):
                # 将状态和轮密钥的半字节转换为整数
                state_val = int(state[i][j], 2) if isinstance(state[i][j], str) else state[i][j]
                key_val = int(round_key[i][j], 2) if isinstance(round_key[i][j], str) else round_key[i][j]
                
                # 异或运算
                result = state_val ^ key_val
                
                # 转换回二进制字符串
                new_state[i][j] = format(result, '04b')
        
        return new_state
    
    @staticmethod
    def key_expansion(key: str) -> list:
        """
        密钥扩展
        """
        if len(key) != 16:
            raise ValueError("密钥必须是16位")
        
        # 分割为两个8位字
        w0 = key[:8]
        w1 = key[8:]
        
        # 计算w2 = w0 ⊕ g(w1)
        w2 = SAESCore.xor_binary(w0, SAESCore.g_function(w1, 1))
        
        # 计算w3 = w2 ⊕ w1
        w3 = SAESCore.xor_binary(w2, w1)
        
        # 计算w4 = w2 ⊕ g(w3)
        w4 = SAESCore.xor_binary(w2, SAESCore.g_function(w3, 2))
        
        # 计算w5 = w4 ⊕ w3
        w5 = SAESCore.xor_binary(w4, w3)
        
        # 组合成轮密钥
        k0 = w0 + w1  # K0
        k1 = w2 + w3  # K1
        k2 = w4 + w5  # K2
        
        return [k0, k1, k2]
    
    @staticmethod
    def g_function(word: str, round_num: int) -> str:
        """
        g函数用于密钥扩展
        """
        if len(word) != 8:
            raise ValueError("输入字必须是8位")
        
        # 分割为两个半字节
        nibble1 = word[:4]
        nibble2 = word[4:]
        
        # 循环左移半字节
        rotated = nibble2 + nibble1
        
        # 半字节代替
        sub_nib1 = SAESCore.nibble_substitution(rotated[:4])
        sub_nib2 = SAESCore.nibble_substitution(rotated[4:])
        
        # 与轮常数异或
        rcon = SAESCore.RCON[round_num - 1]
        rcon_binary = format(rcon, '08b')
        
        result = SAESCore.xor_binary(sub_nib1 + sub_nib2, rcon_binary)
        
        return result
    
    @staticmethod
    def binary_to_state(binary: str) -> list:
        """
        将16位二进制转换为2x2状态矩阵
        """
        if len(binary) != 16:
            raise ValueError("输入必须是16位")
        
        # 按列组织：前8位是第一列，后8位是第二列
        return [
            [binary[0:4], binary[8:12]],   # [s00, s01]
            [binary[4:8], binary[12:16]]   # [s10, s11]
        ]
    
    @staticmethod
    def state_to_binary(state: list) -> str:
        """
        将2x2状态矩阵转换为16位二进制
        """
        # 按列组织转换回二进制
        return (state[0][0] + state[1][0] +   # 第一列
                state[0][1] + state[1][1])    # 第二列
    
    @staticmethod
    def key_to_matrix(key: str) -> list:
        """
        将16位密钥转换为2x2矩阵形式
        """
        return SAESCore.binary_to_state(key)
    
    def encrypt(self, plaintext: str, key: str) -> str:
        """
        S-AES加密
        """
        # 输入验证
        if len(plaintext) != 16 or len(key) != 16:
            raise ValueError("明文和密钥必须是16位二进制")
        
        # 密钥扩展
        round_keys = self.key_expansion(key)
        
        # 初始状态
        state = self.binary_to_state(plaintext)
        
        # 第0轮：轮密钥加 (K0)
        key_matrix0 = self.key_to_matrix(round_keys[0])
        state = self.add_round_key(state, key_matrix0)
        
        # 第1轮：完整轮
        # 半字节代替
        state = [[self.nibble_substitution(state[0][0]), self.nibble_substitution(state[0][1])],
                [self.nibble_substitution(state[1][0]), self.nibble_substitution(state[1][1])]]
        
        # 行移位
        state = self.shift_rows(state)
        
        # 列混淆
        state = self.mix_columns(state)
        
        # 轮密钥加 (K1)
        key_matrix1 = self.key_to_matrix(round_keys[1])
        state = self.add_round_key(state, key_matrix1)
        
        # 第2轮：简化轮
        # 半字节代替
        state = [[self.nibble_substitution(state[0][0]), self.nibble_substitution(state[0][1])],
                [self.nibble_substitution(state[1][0]), self.nibble_substitution(state[1][1])]]
        
        # 行移位
        state = self.shift_rows(state)
        
        # 轮密钥加 (K2)
        key_matrix2 = self.key_to_matrix(round_keys[2])
        state = self.add_round_key(state, key_matrix2)
        
        # 转换为二进制输出
        return self.state_to_binary(state)
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        S-AES解密
        """
        # 输入验证
        if len(ciphertext) != 16 or len(key) != 16:
            raise ValueError("密文和密钥必须是16位二进制")
        
        # 密钥扩展
        round_keys = self.key_expansion(key)
        
        # 初始状态
        state = self.binary_to_state(ciphertext)
        
        # 第0轮：轮密钥加 (K2)
        key_matrix2 = self.key_to_matrix(round_keys[2])
        state = self.add_round_key(state, key_matrix2)
        
        # 第1轮：逆轮
        # 逆行移位
        state = self.inv_shift_rows(state)
        
        # 逆半字节代替
        state = [[self.nibble_substitution(state[0][0], inverse=True), 
                 self.nibble_substitution(state[0][1], inverse=True)],
                [self.nibble_substitution(state[1][0], inverse=True), 
                 self.nibble_substitution(state[1][1], inverse=True)]]
        
        # 轮密钥加 (K1)
        key_matrix1 = self.key_to_matrix(round_keys[1])
        state = self.add_round_key(state, key_matrix1)
        
        # 逆列混淆
        state = self.mix_columns(state, inverse=True)
        
        # 第2轮：逆轮
        # 逆行移位
        state = self.inv_shift_rows(state)
        
        # 逆半字节代替
        state = [[self.nibble_substitution(state[0][0], inverse=True), 
                 self.nibble_substitution(state[0][1], inverse=True)],
                [self.nibble_substitution(state[1][0], inverse=True), 
                 self.nibble_substitution(state[1][1], inverse=True)]]
        
        # 轮密钥加 (K0)
        key_matrix0 = self.key_to_matrix(round_keys[0])
        state = self.add_round_key(state, key_matrix0)
        
        # 转换为二进制输出
        return self.state_to_binary(state)