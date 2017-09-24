
text_path = './2017_09_21_17_19_17_raquel.leandra.perez.Escitalo'
text = open(text_path, 'r')

text = list(text)[0]
print(len(text))
alphabetsize = 26


def scytale_decrypt(cipher_text, key):
    chars = [c for c in cipher_text]
    result = ''
    for i in range(1,key):
        for j in range(i,len(chars),key):
            result += chars[j]
    return result


for i in range(1, 25):
    result = scytale_decrypt(text, i)
    if 'the' in result:
        resul_path = text_path + 'decrypted' + str(i)
        resul_file = open(resul_path, mode='w')
        print(i)
        resul_file.write(result)
        resul_file.close()
