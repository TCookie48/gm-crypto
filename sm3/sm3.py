import struct

# SM3 初始 IV（8 个 32 位字）
IV = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
]

# 常量 T_j：前 16 轮 0x79cc4519，后 48 轮 0x7a879d8a
T = [0x79cc4519] * 16 + [0x7a879d8a] * 48

class SM3:
    """SM3哈希算法封装类，符合工业级项目规范"""

    def hash(self, data: bytes) -> bytes:
        """计算输入数据的SM3哈希值
        :param data: 输入字节串
        :return: 32字节SM3哈希值
        """
        return sm3_hash(data)

    @staticmethod
    def hexhash(data: bytes) -> str:
        """计算哈希并返回十六进制字符串，方便打印/存储
        :param data: 输入字节串
        :return: 64位十六进制哈希字符串
        """
        return sm3_hash(data).hex()

def _rotl(x, n):
    """32 位循环左移"""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _ff(x, y, z, j):
    """布尔函数 FF"""
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (x & z) | (y & z))


def _gg(x, y, z, j):
    """布尔函数 GG"""
    return (x ^ y ^ z) if j <= 15 else ((x & y) | (~x & z))


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _msg_extend(b):
    """消息扩展：16 个字 → 132 个字"""
    w = list(struct.unpack('>16I', b)) + [0] * 116
    for j in range(16, 68):
        w[j] = _p1(w[j-16] ^ w[j-9] ^ _rotl(w[j-3], 15)) ^ _rotl(w[j-13], 7) ^ w[j-6]
    for j in range(68, 132):
        w[j] = w[j-68] ^ w[j-64]
    return w


def _compress(v, w):
    """压缩函数：64 步迭代"""
    a, b, c, d, e, f, g, h = v
    for j in range(64):
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(T[j], j % 32)) & 0xffffffff, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_ff(a, b, c, j) + d + ss2 + w[j+68]) & 0xffffffff
        tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xffffffff
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)
    return [(x ^ y) & 0xffffffff for x, y in zip([a,b,c,d,e,f,g,h], v)]


def sm3_hash(data: bytes) -> bytes:
    """
    SM3 哈希算法
    对标标准：GM/T 0004-2012
    输入：任意长度字节串
    输出：32 字节（256 位）哈希值
    """
    # 1. 消息填充
    l = len(data) * 8
    data = bytearray(data)
    data.append(0x80)  # 补 '1'
    while (len(data) * 8) % 512 != 448:
        data.append(0x00)  # 补 '0'
    data += struct.pack('>Q', l)  # 64 位长度

    # 2. 迭代压缩
    v = list(IV)
    for i in range(0, len(data), 64):
        b = data[i:i+64]
        w = _msg_extend(b)
        v = _compress(v, w)

    # 3. 输出
    return b''.join(struct.pack('>I', x) for x in v)


# 当直接运行这个文件时，测试 "abc"
if __name__ == '__main__':
    # 测试代码
    sm3 = SM3()
    data = b"abc"
    hash_val = sm3.hash(data)
    print(hash_val.hex())


