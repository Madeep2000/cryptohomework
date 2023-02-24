import base64
import binascii
from gmssl import sm2, func
#16进制的公钥和私钥
#private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
#public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

private_key = '21c47db3ec79088441f8576710bac4f70e89d7fe0835aa28eb78a1b5fa74d1c4'
public_key = '7e1188ac6eb31e6926304663e85dce3a745f0e911c1fef40a40a0d480e0350ae65c004d0775d9fbc5e5d927941e72b4c07e38114ab3509af31f8eaa8edb3b145'

sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)

data = "华南师范大学计算机学院网络工程系".encode()
print(data)

#data = b"华南师范大学计算机学院网络工程系" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str) #  16进制
print(sign)
assert sm2_crypt.verify(sign, data) #  16进制