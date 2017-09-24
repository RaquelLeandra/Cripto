import numpy as np


text_path = './2017_09_21_17_19_17_raquel.leandra.perez.Cesar'
text = np.loadtxt(text_path, dtype=np.str)

print(text[0:-1])
alphabetsize = 26


def add(c, x):
    return chr((ord(c)+x-ord('a'))% alphabetsize + ord('a'))


def addmay(c, x):
    return chr((ord(c)+x-ord('A'))% alphabetsize + ord('A'))


def decrypt_cesar(text):
    keys = ['the', 'and']

    for i in range(1, alphabetsize):
        result = ''
        resul_path = text_path + 'decrypted' + str(i)
        resul_file = open(resul_path, mode='w')
        for word in text:
            newword = ''
            for letter in word:
                if ord(letter) <= ord('z') and ord(letter) >= ord('a'):
                    newword += (add(letter, i))
                elif ord(letter) <= ord('Z') and ord(letter) >= ord('A'):
                    newword += (addmay(letter, i))
                else:
                    newword += letter

            result = result + ' ' + newword
        print(result)
        resul_file.write(result)
        resul_file.close()

decrypt_cesar(text)

