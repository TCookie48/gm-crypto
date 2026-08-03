# GM-Crypto

国密算法（SM2/SM3/SM4）的纯Python学习型实现。

> ⚠️ 本项目用于学习和标准符合性验证，未通过国家密码管理局商用密码检测中心认证，
> 生产环境请使用GmSSL、tjfoc/gmsm等经认证的商用密码产品。

## 对标标准
- SM3: GM/T 0004-2012 / GB/T 32905-2016
- SM4分组密码（通过 GM/T 0002-2012 官方测试向量验证）
- [ ] SM2椭圆曲线算法（待开发）

## 使用
### SM3 哈希计算
```
python
# 从 sm3 包导入 SM3 类
from sm3 import SM3

# 实例化并运行
sm3 = SM3()
hash_result = sm3.hash(b"abc")
print(hash_result.hex())
```

### SM4 ECB 模式加密
```
python
from sm4 import SM4
key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
plaintext = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
sm4 = SM4(key)
ciphertext = sm4.encrypt_block(plaintext)
print(ciphertext.hex().upper()) # 681EDF34D206965E86B3E94F536E4246
```


## 开发进度
本项目由山东师范大学网络空间安全专业在校生独立开发，旨在深入理解国密算法底层原理。
