from itertools import permutations

text_path = './2017_09_21_17_19_17_raquel.leandra.perez.Vigenere'
text = open(text_path, 'r')
decrypted_path = './Vigenere/decrypded'
text = list(text)[0]
print(len(text))
alphabetsize = 26


def add(c, x):
    if c.islower():
        return chr((ord(c)-x-ord('a')) % alphabetsize + ord('a'))
    else:
        return chr((ord(c)-x-ord('A')) % alphabetsize + ord('A'))


def vigenere_decrypt(cipher_text, key):
    chars = [c for c in cipher_text]
    result = ''
    keysize = len(key)
    j = 0
    for i in range(0, len(chars)):
        if j == keysize:
            j = 0
        if chars[i].isalpha():
            result += add(chars[i], key[j])
            j +=1
        else:
            result += chars[i]

    return result
"""Testing that the algorithm works

key = 'LEMON'
numkey = [ord(c) - ord('A') for c in key]
charkey = [chr(c + ord('A')) for c in numkey]
cipther_text = 'LXFOPV EF RNHR'
print(vigenere_decrypt(cipther_text,numkey))
"""

# Brute force to find the key
keyword = 'Machine'
for i in permutations(range(0, 26), 10):
    decrypted = vigenere_decrypt(text, i)
    if keyword in decrypted:
        decrypted_path = './Vigenere/decrypted' + str(i)
        decrypted_text = open(decrypted_path, 'w')
        decrypted_text.write(decrypted)
        decrypted_text.close()

key = [3, 8, 12, 4, 13, 18, 8, 14, 13, 18]
# key = dimensions