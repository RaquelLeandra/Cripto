from hashlib import sha256
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import os
def aes_encrpyt():
    IV = (os.urandom(16))
    kiv = (os.urandom(2))
    concat = IV
    concat += kiv
    KS = sha256(concat).hexdigest()[0:16]
    kf = open('./Data/keyfile.key', 'w').write(KS)
    kivf = open('./Data/kivfile.key', 'wb').write(kiv)
    aes_encryptor = AES.new(KS, AES.MODE_CBC, IV)
    message = open("./Data/test.txt", 'rb').read()
    newtext = PKCS7Encoder().encode(message)
    cryptogram = aes_encryptor.encrypt(newtext)
    result = IV
    result += cryptogram
    fp = open('./Data/file.enc', 'wb')
    fp.write(result)
    return result