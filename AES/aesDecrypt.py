import base64
from Crypto import Random
from hashlib import sha256
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import os
import magic


cyphertextObject = open("./Data/2017_09_26_13_22_56_raquel.leandra.perez.enc", 'rb')
originalcyphertext = cyphertextObject.read()

keyObject = open("./Data/2017_09_26_13_22_56_raquel.leandra.perez.key", 'rb')
key = keyObject.read()
iv = originalcyphertext[0:16]
cyphertext = originalcyphertext[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)

plain_text = cipher.decrypt(cyphertext)

output = open("./Data/dec.output", 'wb').write(plain_text)


cyphertextbd = open("./Data/2017_09_26_13_22_56_raquel.leandra.perez.puerta_trasera.enc", 'rb').read()


def decode(bytestring, k=16):
    """
    Remove the PKCS#7 padding from a text bytestring.
    """

    val = bytestring[-1]
    l = len(bytestring) - val
    return bytestring[:l]


def encode(bytestring, k=16):
    """
    Pad an input bytestring according to PKCS#7

    """
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)

def yoloaes_encrpyt():
    IV = (os.urandom(16))
    kiv = (os.urandom(2))
    concat = IV
    concat += kiv
    KS = sha256(concat).hexdigest()[0:16]
    kf = open('./Data/keyfile.key', 'w').write(KS)
    kivf = open('./Data/kivfile.key', 'wb').write(kiv)
    aes_encryptor = AES.new(KS, AES.MODE_CBC, IV)
    message = open("./Data/dec.output", 'rb').read()
    encoder = PKCS7Encoder()
    newtext = encode(message)
    cryptogram = aes_encryptor.encrypt(newtext)
    result = IV

    result += cryptogram
    fp = open('./Data/deathfile.enc', 'wb')
    fp.write(result)
    return result

def yoloaes_decrypt( kiv):
    encryptedfile = open('./Data/2017_09_26_13_22_56_raquel.leandra.perez.puerta_trasera.enc', 'rb').read()
    IV = encryptedfile[0:16]
    crytogram = encryptedfile[16:]
    concat = IV
    concat += kiv
    key = sha256(concat).hexdigest()[0:16]
    aes_encryptor = AES.new(key, AES.MODE_CBC, IV)
    decrypted = aes_encryptor.decrypt(crytogram)
    #decrypted = decode(decrypted)
    f = open('./Data/goodfile.dec', 'wb').write(decrypted)
    with magic.Magic() as m:
        t = m.id_filename('./Data/goodfile.dec')
    if t != 'data':
        decrypted = decode(decrypted)
        g = open('./Data/Decrypted/goodfile'+ str(list(kiv))+'.dec', 'wb').write(decrypted)
    return decrypted

dec = yoloaes_encrpyt()
kivf = open('./Data/kivfile.key', 'rb').read()

t = 'data'
count = 0

def conditions(t,text):
    if text[-1] > 16:
        return True
    #return t[0:4] != 'JPEG' and t[0:3] != 'PNG'
    #if t != 'data':
    #    return t[0:4] != 'JPEG' and t[0:3] != 'PNG'
    return True

#
for i in range(0,255):
    for j in range(0,255):
        kiv = bytes([i, j])
        yoloaes_decrypt(kiv)
        if count %1000 == 0:
            print(count)
        count +=1


jpgtoken = b'\xff\xd8\xff'
pngtoken = b'\x89\x50\x4e\x47'
image = b'\xc2\xd6'