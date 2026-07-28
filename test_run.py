from sm3 import SM3


def test_sm3():
    sm3 = SM3()
    # 输入是字节串（b前缀）
    input_bytes = b"abc"
    # 计算哈希（返回字节串）
    hash_bytes = sm3.hash(input_bytes)
    # 转成十六进制字符串（方便阅读和对比）
    hash_hex = hash_bytes.hex()

    # 打印的时候分别处理：原始输入转字符串，哈希值转十六进制字符串
    print(f"字符串 'abc'（字节形式：{input_bytes}）的 SM3 哈希值是：")
    print(hash_hex)

    # 国标官方测试向量（十六进制字符串）
    expected_hex = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

    if hash_hex == expected_hex:
        print("\n恭喜！测试100%通过，你的SM3实现完全符合国标GM/T 0004-2012！")
    else:
        print("\n测试未通过，请检查代码。")


if __name__ == '__main__':
    test_sm3()