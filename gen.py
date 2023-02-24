from gmssl import sm2, func

# 继承SM2类
class Generator_SM2_Key(sm2.CryptSM2):
    def __init__(self,private_key = None, public_key = None, ecc_table = sm2.default_ecc_table, mode = 0):
        super().__init__(private_key,public_key,ecc_table)
    
    def get_private_key(self):
        if self.private_key is None:
            self.private_key = func.random_hex(self.para_len) # d∈[1, n-2]
        return self.private_key
    
    def get_public_key(self):
        if self.public_key is None:
            self.public_key = self._kg(int(self.get_private_key(), 16), self.ecc_table['g']) # P=[d]G
        return self.public_key


sm2key = Generator_SM2_Key()
private_key = sm2key.get_private_key()
public_key = sm2key.get_public_key()
print('private_key:',private_key)
print('public_key: ',public_key)

sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)

#数据和加密后数据为bytes类型
data = bytes.fromhex('91cacfd230122fc832fc1b0b2aa07d93')
enc_data = sm2_crypt.encrypt(data)
dec_data =sm2_crypt.decrypt(enc_data)
assert dec_data == data
print('Enc: ',enc_data.hex())

random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign_with_sm3(data, random_hex_str)
assert sm2_crypt.verify_with_sm3(sign, data)
print('Sign:',sign)
