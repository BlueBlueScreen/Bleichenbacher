from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from PKCS.formatting import *

class Oracle:
    def __init__(self):
        self.key=RSA.generate(2048)
        self.pkcs=PKCS1_v1_5.new(self.key)
        self.secret=b'This is a secret message'
        self.cipher=self.pkcs.encrypt(self.secret)

    def get_n(self)->int:
        #返回RSA模数
        return self.key.n

    def get_k(self)->int:
        #返回模数的字节长
        return self.key.size_in_bytes()

    def get_e(self)->int:
        #返回RSA指数
        return self.key.e

    def eavesdrop(self)->bytes:
        #敌手窃听到密文
        return self.cipher

    #填充预言机的核心功能
    def decrypt(self, ciphertext: bytes) -> bool:
        if len(ciphertext) != self.get_k():
            return False

        try:
            c = os2ip(ciphertext)
            m = pow(c, self.key.d, self.key.n)  # 手动 RSA 解密
            em = i2osp(m, self.get_k())  # 转成 k 字节表示
        except Exception:
            return False

        # 开始检查 PKCS#1 v1.5 padding
        if not em.startswith(b'\x00\x02'):
            return False
        sep = em.find(b'\x00', 2)
        if sep < 10:  # PS 长度 < 8 不合法
            return False

        return True
