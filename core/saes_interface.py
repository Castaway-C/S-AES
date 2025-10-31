from .saes_core import SAESCore


class SAESInterface:
    """
    S-AES算法接口类
    """
    
    def __init__(self):
        self.core = SAESCore()
    
    def encrypt(self, plaintext: str, key: str) -> str:
        """
        基本加密
        """
        return self.core.encrypt(plaintext, key)
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        """
        基本解密
        """
        return self.core.decrypt(ciphertext, key)
    
    def encrypt_ascii(self, text: str, key: str) -> str:
        """
        ASCII文本加密
        """
        # 将文本转换为二进制
        binary_text = self.core.text_to_binary(text)
        
        # 确保密钥是16位二进制
        if len(key) != 16 or not all(bit in '01' for bit in key):
            raise ValueError("密钥必须是16位二进制")
        
        # 分组加密
        encrypted_binary = ''
        for i in range(0, len(binary_text), 16):
            block = binary_text[i:i+16]
            # 如果最后一个块不足16位，进行填充
            if len(block) < 16:
                block = block + '0' * (16 - len(block))
            encrypted_block = self.core.encrypt(block, key)
            encrypted_binary += encrypted_block
        
        # 将加密后的二进制转换回ASCII字符串
        return self.core.binary_to_text(encrypted_binary)
    
    def decrypt_ascii(self, ciphertext: str, key: str) -> str:
        """
        ASCII文本解密
        """
        # 将密文字符串转换为二进制
        binary_cipher = self.core.text_to_binary(ciphertext)
        
        # 确保密钥是16位二进制
        if len(key) != 16 or not all(bit in '01' for bit in key):
            raise ValueError("密钥必须是16位二进制")
        
        # 分组解密（每组16位）
        decrypted_binary = ''
        for i in range(0, len(binary_cipher), 16):
            block = binary_cipher[i:i+16]
            if len(block) == 16:  # 只处理完整的16位块
                decrypted_block = self.core.decrypt(block, key)
                decrypted_binary += decrypted_block
        
        # 将解密后的二进制转换回ASCII字符串
        return self.core.binary_to_text(decrypted_binary)
    
    def double_encrypt(self, plaintext: str, key: str) -> str:
        """
        双重加密
        """
        if len(key) != 32:
            raise ValueError("双重加密密钥必须是32位")
        
        # 分割密钥
        key1 = key[:16]
        key2 = key[16:]
        
        # 第一次加密
        intermediate = self.core.encrypt(plaintext, key1)
        # 第二次加密
        return self.core.encrypt(intermediate, key2)
    
    def double_decrypt(self, ciphertext: str, key: str) -> str:
        """
        双重解密
        """
        if len(key) != 32:
            raise ValueError("双重解密密钥必须是32位")
        
        # 分割密钥
        key1 = key[:16]
        key2 = key[16:]
        
        # 第一次解密
        intermediate = self.core.decrypt(ciphertext, key2)
        # 第二次解密
        return self.core.decrypt(intermediate, key1)
    
    def meet_in_middle_attack(self, plaintext: str, ciphertext: str) -> list:
        """
        中间相遇攻击
        """
        encryption_map = {}
        found_keys = []

        # 加密阶段


        for k1_int in range(65536):
            k1 = format(k1_int, '016b')
            intermediate = self.core.encrypt(plaintext, k1)
            # 存储 E(K1, P) -> K1
            encryption_map[intermediate] = k1

        # 解密阶段
        for k2_int in range(65536):  # 2^16
            k2 = format(k2_int, '016b')
            intermediate = self.core.decrypt(ciphertext, k2)

            if intermediate in encryption_map:
                k1_match = encryption_map[intermediate]
                # 找到匹配! K1 = k1_match, K2 = k2
                found_keys.append((k1_match, k2))

        return found_keys

    def triple_encrypt(self, plaintext: str, key: str) -> str:
        """
        三重加密
        """
        if len(key) != 48:
            raise ValueError("三重加密密钥必须是48位")

        # 分割密钥
        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]

        # 加密-解密-加密模式
        step1 = self.core.encrypt(plaintext, key1)
        step2 = self.core.decrypt(step1, key2)
        return self.core.encrypt(step2, key3)

    def triple_decrypt(self, ciphertext: str, key: str) -> str:
        """
        三重解密
        """
        if len(key) != 48:
            raise ValueError("三重解密密钥必须是48位")

        # 分割密钥
        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]

        # 解密-加密-解密模式
        step1 = self.core.decrypt(ciphertext, key3)
        step2 = self.core.encrypt(step1, key2)
        return self.core.decrypt(step2, key1)

    def cbc_encrypt(self, plaintext: str, key: str, iv: str) -> str:
        """
        CBC模式加密
        """
        # 将文本转换为二进制
        binary_plain = self.core.text_to_binary(plaintext)

        # 分组处理
        previous_block = iv
        encrypted_blocks = []

        for i in range(0, len(binary_plain), 16):
            block = binary_plain[i:i+16]
            # 填充处理
            if len(block) < 16:
                block = block + '0' * (16 - len(block))

            # CBC模式：与前一个密文块异或
            xor_block = self.core.xor_binary(block, previous_block)

            # 加密
            encrypted_block = self.core.encrypt(xor_block, key)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block

        # 组合所有密文块
        encrypted_binary = ''.join(encrypted_blocks)

        # 转换为ASCII字符串返回
        return self.core.binary_to_text(encrypted_binary)

    def cbc_decrypt(self, ciphertext: str, key: str, iv: str) -> str:
        """
        CBC模式解密
        """
        # 将密文字符串转换为二进制
        binary_cipher = self.core.text_to_binary(ciphertext)

        # 分组处理
        previous_block = iv
        decrypted_blocks = []

        for i in range(0, len(binary_cipher), 16):
            block = binary_cipher[i:i+16]
            if len(block) == 16:
                # 解密
                decrypted_block = self.core.decrypt(block, key)

                # CBC模式：与前一个密文块异或
                plain_block = self.core.xor_binary(decrypted_block, previous_block)
                decrypted_blocks.append(plain_block)

                previous_block = block

        # 组合所有明文块
        decrypted_binary = ''.join(decrypted_blocks)

        # 转换为ASCII字符串返回
        return self.core.binary_to_text(decrypted_binary)

    def cbc_tamper_test(self, plaintext: str, key: str, iv: str) -> str:
        """
        CBC篡改测试
        """
        # 正常加密
        ciphertext = self.cbc_encrypt(plaintext, key, iv)
        normal_decryption = self.cbc_decrypt(ciphertext, key, iv)

        # 篡改密文（修改中间的一个字节）
        binary_cipher = self.core.text_to_binary(ciphertext)

        if len(binary_cipher) >= 32:  # 确保有足够的长度进行篡改
            # 篡改第二个块（从第16位开始）
            tamper_pattern = '0000000100000001' # 篡改第1个和第8个bit
            tampered_cipher = (binary_cipher[:16] +
                             self.core.xor_binary(binary_cipher[16:32], tamper_pattern) +
                             binary_cipher[32:])

            # 将篡改后的密文转换回字符串
            tampered_cipher_text = self.core.binary_to_text(tampered_cipher)

            # 解密篡改后的密文
            tampered_plaintext = self.cbc_decrypt(tampered_cipher_text, key, iv)

            result = (f"正常解密结果:\n{normal_decryption}\n\n"
                     f"篡改的密文块: 第2块 (C1)\n"
                     f"篡改方式: C1' = C1 XOR {tamper_pattern}\n\n"
                     f"篡改后解密结果:\n{tampered_plaintext}\n\n"
                     f"分析:\n"
                     f"1. 解密 C1' 对应的明文块 P1' 完全损坏 (因为 P1' = D(K, C1') XOR C0)。\n"
                     f"2. 解密 C2 对应的明文块 P2' 发生位错误 (因为 P2' = D(K, C2) XOR C1')。\n"
                     f"3. 篡改在一个密文块(C1)中，导致两个明文块(P1'和P2')被破坏。")
        else:
            result = "文本太短（不足2个分组），无法进行有意义的篡改测试"
        
        return result