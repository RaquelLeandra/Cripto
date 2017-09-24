
import math


def scytale_encrypt(plain_text, key):
    chars = [c for c in plain_text if c not in ('.','?','!',':',';',"'")]
    chunks = math.ceil(len(chars) / float(key))
    inters, i, j = [], 1, 1

    while i <= chunks:
        inters.append(tuple(chars[j - 1:(j + key) - 1]))
        i += 1
        j += key

    cipher, k = [], 0
    while k < key:
        l = 0
        while l < chunks:
            if k >= len(inters[l]):
                cipher.append('+')
            else:
                cipher.append(inters[l][k])
            l += 1
        k += 1

    return ''.join(cipher)


def scytale_decrypt(cipher_text, key):
    chars = [c for c in cipher_text]
    chunks = int(math.ceil(len(chars) / float(key)))
    inters, i, j = [], 1, 1

    while i <= key:
        inters.append(tuple(chars[j - 1:(j + chunks) -1]))
        i += 1
        j += chunks

    plain, k = [], 0
    while k < chunks:
        l = 0
        while l < len(inters):
            plain.append(inters[l][k])
            l += 1
        k += 1

    return ''.join(plain)


def main():
    s = "Jonas Gorauskas, Danya Peters, Ava Gorauskas, Eli Gorauskas, Ian Gorauskas"
    c = scytale_encrypt(s, 4)
    d = scytale_decrypt(c, 4)

    print ("%s\n%s\n%s" % (s,c,d))


if __name__ == '__main__':
    main()