# GM-Crypto

国密算法（SM2/SM3/SM4）的纯Python学习型实现。

> ⚠️ 本项目用于学习和标准符合性验证，未通过国家密码管理局商用密码检测中心认证，
> 生产环境请使用GmSSL、tjfoc/gmsm等经认证的商用密码产品。

## 对标标准
- SM3: GM/T 0004-2012 / GB/T 32905-2016
- SM4: GM/T 0002-2012 / GB/T 32907-2016
- SM2: GM/T 0003-2012 / GB/T 32918-2016

## 功能
- [x] SM3哈希算法（通过GM/T 0004-2012官方测试向量验证）
- [ ] SM4分组密码（开发中）
- [ ] SM2椭圆曲线算法（待开发）

## 使用
```
from sm3 import SM3
sm3 = SM3()
hash_result = sm3.hash(b"abc")
print(hash_result.hex()) # 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```