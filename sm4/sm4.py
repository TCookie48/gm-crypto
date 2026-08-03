class SM4:
    # S盒（GM/T 0002-2012 标准固定值）
    SBOX = [
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
    ]

    # 系统参数 FK
    FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

    # 固定参数 CK
    CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    ]

    def __init__(self, key: bytes):
        """
        初始化 SM4，传入 16 字节密钥
        对标标准：GM/T 0002-2012
        """
        if len(key) != 16:
            raise ValueError("SM4 密钥长度必须为 16 字节（128 位）")
        self.key = key
        self.round_keys = self._key_expansion(key)

    @staticmethod
    def _rotl(x, n):
        """32 位循环左移"""
        n = n % 32
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @classmethod
    def _sbox_byte(cls, b):
        """查 S 盒"""
        return cls.SBOX[b]

    @classmethod
    def _byte_sub(cls, word):
        """对一个 32 位字做 S 盒替换，返回 32 位字"""
        b0 = (word >> 24) & 0xFF
        b1 = (word >> 16) & 0xFF
        b2 = (word >> 8) & 0xFF
        b3 = word & 0xFF
        sb0 = cls._sbox_byte(b0)
        sb1 = cls._sbox_byte(b1)
        sb2 = cls._sbox_byte(b2)
        sb3 = cls._sbox_byte(b3)
        return (sb0 << 24) | (sb1 << 16) | (sb2 << 8) | sb3

    @classmethod
    def _round_func(cls, X, rk):
        """一轮非线性变换函数 T"""
        # 1. S 盒替换
        s = cls._byte_sub( X ^ rk)
        # 2. 线性变换 L：L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
        L = s ^ cls._rotl(s, 2) ^ cls._rotl(s, 10) ^ cls._rotl(s, 18) ^ cls._rotl(s, 24)
        return L

    def _key_expansion(self, key: bytes):
        """密钥扩展：生成 32 轮子密钥"""
        # 1. 将 16 字节密钥转为 4 个 32 位字 K0-K3
        K = [
            int.from_bytes(key[0:4], 'big'),
            int.from_bytes(key[4:8], 'big'),
            int.from_bytes(key[8:12], 'big'),
            int.from_bytes(key[12:16], 'big')
        ]
        # 2. (K0 ^ FK0), (K1 ^ FK1), (K2 ^ FK2), (K3 ^ FK3)
        K[0] ^= self.FK[0]
        K[1] ^= self.FK[1]
        K[2] ^= self.FK[2]
        K[3] ^= self.FK[3]

        round_keys = []
        # 3. 迭代 32 轮生成 rk0-rk31
        for i in range(32):
            # 使用轮函数 T'（CK 异或后做 S 盒和 L' 变换）
            # T' 的 L' 与 T 的 L 略有不同：L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)
            tmp = K[1] ^ K[2] ^ K[3] ^ self.CK[i]
            # S 盒替换
            s = self._byte_sub(tmp)
            # L' 变换
            T_prime = s ^ self._rotl(s, 13) ^ self._rotl(s, 23)
            rk = K[0] ^ T_prime
            round_keys.append(rk)
            # 移位：K0,K1,K2,K3 -> K1,K2,K3,rk
            K[0], K[1], K[2], K[3] = K[1], K[2], K[3], rk
        return round_keys

    def _one_round(self, X0, X1, X2, X3, rk):
        """SM4 一轮加密：X0 ^ T(X1 ^ X2 ^ X3 ^ rk)"""
        temp = X1 ^ X2 ^ X3 ^ rk
        # S 盒替换
        s = self._byte_sub(temp)
        # 线性变换 L
        t = s ^ self._rotl(s, 2) ^ self._rotl(s, 10) ^ self._rotl(s, 18) ^ self._rotl(s, 24)
        return X0 ^ t

    def encrypt_block(self, block: bytes) -> bytes:
        """加密单个 16 字节分组（ECB 模式基础）"""
        if len(block) != 16:
            raise ValueError("SM4 分组长度必须为 16 字节")
        # 明文字节转为 4 个 32 位字 X0-X3
        X = [
            int.from_bytes(block[0:4], 'big'),
            int.from_bytes(block[4:8], 'big'),
            int.from_bytes(block[8:12], 'big'),
            int.from_bytes(block[12:16], 'big')
        ]
        # 32 轮迭代，使用 rk0-rk31
        for i in range(32):
            X_next = self._one_round(X[0], X[1], X[2], X[3], self.round_keys[i])
            X = [X[1], X[2], X[3], X_next]
        out = (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]
        return out.to_bytes(16, 'big')

    def decrypt_block(self, block: bytes) -> bytes:
        """解密单个 16 字节分组（使用 rk31-rk0 逆序）"""
        if len(block) != 16:
            raise ValueError("SM4 分组长度必须为 16 字节")
        X = [
            int.from_bytes(block[0:4], 'big'),
            int.from_bytes(block[4:8], 'big'),
            int.from_bytes(block[8:12], 'big'),
            int.from_bytes(block[12:16], 'big')
        ]
        # 32 轮迭代，使用 rk31-rk0（逆序）
        for i in range(32):
            rk = self.round_keys[31 - i]
            X_next = self._one_round(X[0], X[1], X[2], X[3], rk)
            X = [X[1], X[2], X[3], X_next]
        out = (X[3] << 96) | (X[2] << 64) | (X[1] << 32) | X[0]
        return out.to_bytes(16, 'big')

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB 模式加密（需自行保证明文长度为 16 的倍数）"""
        if len(plaintext) % 16 != 0:
            raise ValueError("ECB 模式明文长度必须是 16 字节的倍数，请先填充")
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self.encrypt_block(plaintext[i:i + 16])
        return ciphertext

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB 模式解密"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是 16 字节的倍数")
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self.decrypt_block(ciphertext[i:i + 16])
        return plaintext

    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        """PKCS7 填充"""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """PKCS7 去填充"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("无效的 PKCS7 填充")
        return data[:-pad_len]


if __name__ == '__main__':
    # 国标 GM/T 0002-2012 附录 A.1 测试向量
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    plaintext = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    expected = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

    sm4 = SM4(key)
    ciphertext = sm4.encrypt_block(plaintext)
    print("SM4('0123456789ABCDEFFEDCBA9876543210') =")
    print(ciphertext.hex().upper())
    print()
    print("期望输出：")
    print(expected.hex().upper())
    print()
    print("测试通过" if ciphertext == expected else "测试失败")


    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """CBC 模式加密"""
        if len(iv) != 16:
            raise ValueError("IV 长度必须为 16 字节")
        if len(plaintext) % 16 != 0:
            raise ValueError("CBC 模式明文长度必须是 16 字节的倍数，请先填充")

        ciphertext = b''
        prev = iv
        for i in range(0, len(plaintext), 16):
            block = bytes(a ^ b for a, b in zip(plaintext[i:i + 16], prev))
            encrypted = self.encrypt_block(block)
            ciphertext += encrypted
            prev = encrypted
        return ciphertext


    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CBC 模式解密"""
        if len(iv) != 16:
            raise ValueError("IV 长度必须为 16 字节")
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是 16 字节的倍数")

        plaintext = b''
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted = self.decrypt_block(block)
            plaintext += bytes(a ^ b for a, b in zip(decrypted, prev))
            prev = block
        return plaintext