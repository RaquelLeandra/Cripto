"""
Este file contiene parte de el código necesario para la práctica de criptografía de
clave secreta:
- Las operaciones de GF(2^8)
- El AES
"""

import numpy as np
from time import time
from copy import copy
from random import randint
import os
from Crypto.Cipher import AES as aes

from matplotlib import pyplot as plt

base = 256
# El polinimo mínimo, en int es 283
m = [1, 0, 0, 0, 1, 1, 0, 1, 1]


def int_to_bin(a):
    # Entero a lista
    elembin = bin(a)[2:len(bin(a))]
    return list(map(int, elembin))


def array_to_string(a):
    return ''.join(str(e) for e in a)


def int_to_string(a):
    # int to string binary
    return bin(a)


def bin_to_int(a):
    # lista a entero
    b = array_to_string(a)
    return int(b, 2)


def GF_product_p(a, b):
    res = 0
    binb = int_to_bin(b)
    for i in range(0, len(binb)):
        if binb[len(binb) - i - 1]:
            res ^= a
        if a & 128:
            a = (a << 1) ^ 283
        else:
            a <<= 1
    return res


log = {}
exp = {}


def GF_tables():
    exp[0] = 1
    log[1] = 3
    for i in range(1, 255):
        a = GF_product_p(exp[i - 1], 3)
        exp[i] = a
        log[a] = i
    return exp, log


def GF_product_t(a, b):
    if len(log) == 0:
        GF_tables()
    i = log[a]
    j = log[b]
    return exp[((i + j) % 255)]


def GF_generator():
    gen = []
    for i in range(0, 255):
        if i % 2:
            gen.append(i)
    return gen


def GF_invers(a):
    if a == 0:
        return a
    else:
        i = log[a]
        i = 255 - i
        return exp[i]


def genTables():
    """
    Esta función me genera las tablas que pide el ejercicio en formato latex
    (Es cuqui :3)
    :return:
    """
    print('\\begin{table}[] \n \centering \n'
          ' \\begin{tabular}{lll} '
          '\n Valores & Producto original & Producto con  Tablas \\\\')
    test = [0x02, 0x03, 0x09, 0x0B, 0x0D, 0x0E]
    tabletimeinitial = time()
    tabletime = []
    GF_tables()
    for t in test:
        for a in range(1, 255):
            GF_product_t(a, t)
        tabletime.append(time() - tabletimeinitial)
        tabletimeinitial = time()

    prodinitialtime = time()
    prodtime = []
    for t in test:
        for a in range(1, 255):
            GF_product_p(a, t)
        prodtime.append(time() - prodinitialtime)
        prodinitialtime = time()

    for i in range(0, len(test)):
        print(str(test[i]) + ' & ' + str(prodtime[i]) + ' & '
              + str(tabletime[i]) + ' \\\\')
    print('Total & ' + str(np.sum(prodtime)) + ' & ' + str(np.sum(tabletime)) +
          ' \n \\end{tabular}  \n \\end{table}'
          )


class AES:
    def __init__(self, bytesub, shiftRow, mixColumn):
        self.bytesub = bytesub
        self.shiftRow = shiftRow
        self.mixColu = mixColumn
        # valid key sizes
        self.keySize = dict(SIZE_128=16, SIZE_192=24, SIZE_256=32)

        # S-box and Inverse S-box (S is for Substitution)
        self.S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca,
                  0x82, 0xc9,
                  0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
                  0x36, 0x3f,
                  0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
                  0x9a, 0x07,
                  0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b,
                  0xd6, 0xb3,
                  0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a,
                  0x4c, 0x58,
                  0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                  0x51, 0xa3,
                  0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13,
                  0xec, 0x5f,
                  0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
                  0x90, 0x88,
                  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
                  0xd3, 0xac,
                  0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
                  0x65, 0x7a,
                  0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b,
                  0x8a, 0x70,
                  0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8,
                  0x98, 0x11,
                  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf,
                  0xe6, 0x42,
                  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

        self.Si = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c,
                   0xe3, 0x39,
                   0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
                   0xa6, 0xc2,
                   0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                   0xb2, 0x76,
                   0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4,
                   0x5c, 0xcc,
                   0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7,
                   0x8d, 0x9d,
                   0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                   0xd0, 0x2c,
                   0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11,
                   0x41, 0x4f,
                   0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
                   0x35, 0x85,
                   0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
                   0xb7, 0x62,
                   0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
                   0x78, 0xcd,
                   0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec,
                   0x5f, 0x60,
                   0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0,
                   0x3b, 0x4d,
                   0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba,
                   0x77, 0xd6,
                   0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

        # Falta poner que es rcon
        self.rcon = [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
        ]

    def rotate(self, word):
        """ Rijndael's key schedule rotate operation.

        Rotate a word eight bits to the left: eg, rotate(1d2c3a4f) == 2c3a4f1d
        Word is an char list of size 4 (32 bits overall).
        """
        return word[1:] + word[:1]

    def core(self, word, iteration):
        """Key schedule core."""
        # rotate the 32-bit word 8 bits to the left
        word = self.rotate(word)
        # apply S-Box substitution on all 4 parts of the 32-bit word
        for i in range(4):
            word[i] = self.S[word[i]]
        # XOR the output of the rcon operation with i to the first part
        # (leftmost) only
        word[0] = word[0] ^ self.rcon[iteration]
        return word

    def expandKey(self, key):
        """Rijndael's key expansion.

        Expands an 128,192,256 key into an 176,208,240 bytes key

        expandedKey is a char list of large enough size,
        key is the non-expanded key.
        """
        size = len(key)
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None

        expandedKeySize = 16 * (nbrRounds + 1)
        # current expanded keySize, in bytes
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the 16, 24, 32 bytes of the expanded key to the input key
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # assign the previous 4 bytes to the temporary value t
            t = expandedKey[currentSize - 4:currentSize]

            # every 16,24,32 bytes we apply the core schedule to t
            # and increment rconIteration afterwards
            if currentSize % size == 0:
                t = self.core(t, rconIteration)
                rconIteration += 1
            # For 256-bit keys, we add an extra sbox to the calculation
            if size == self.keySize["SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): t[l] = self.S[t[l]]

            # We XOR t with the four-byte block 16,24,32 bytes before the new
            # expanded key.  This becomes the next four bytes in the expanded
            # key.
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                                           t[m]
                currentSize += 1

        return expandedKey

    def expandKeyInv(self, key):
        """Rijndael's key expansion.

        Expands an 128,192,256 key into an 176,208,240 bytes key

        expandedKey is a char list of large enough size,
        key is the non-expanded key.
        """
        size = len(key)
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None

        expandedKeySize = 16 * (nbrRounds + 1)
        # current expanded keySize, in bytes
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the 16, 24, 32 bytes of the expanded key to the input key
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # assign the previous 4 bytes to the temporary value t
            t = expandedKey[currentSize - 4:currentSize]

            # every 16,24,32 bytes we apply the core schedule to t
            # and increment rconIteration afterwards
            if currentSize % size == 0:
                t = self.core(t, rconIteration)
                rconIteration += 1
            # For 256-bit keys, we add an extra sbox to the calculation
            if size == self.keySize["SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): t[l] = self.S[t[l]]

            # We XOR t with the four-byte block 16,24,32 bytes before the new
            # expanded key.  This becomes the next four bytes in the expanded
            # key.
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                                           t[m]
                currentSize += 1
            dw = expandedKey
            for i in range(1, nbrRounds - 1):
                expandedKey = self.mixColumnInv(dw[i * 16: (i + 1) * 16 - 1])
        return expandedKey

    def createRoundKey(self, expandedKey, roundKeyPointer):
        """Create a round key.
        Creates a round key from the given expanded key and the
        position within the expanded key.
        """
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[i * 4 + j] = expandedKey[roundKeyPointer + i * 4 + j]
        # print('rouundkey' , roundKeyPointer/16, [hex(k) for k in roundKey])
        return roundKey

    def addRoundKey(self, state, roundkey):
        """Adds the round key to the state"""
        return [state[i] ^ roundkey[i] for i in range(len(state))]

    def ByteSub(self, state):
        if self.bytesub:
            return [self.S[state[i]] for i in range(0, len(state))]
        else:
            return state

    def ByteSubInv(self, state):
        return [self.Si[state[i]] for i in range(0, len(state))]

    # def shiftRow(self, state, statePointer, nbr):
    #     for i in range(nbr):
    #         state[statePointer:statePointer+4] = \
    #                 state[statePointer+1:statePointer+4] + \
    #                 state[statePointer:statePointer+1]
    #     return state
    #
    # def ShiftRows(self, state):
    #     for i in range(4):
    #         state = self.shiftRow(state, i*4, i)
    #     return state

    def rotateWord(self, word, n):
        newpotato = []
        for i in range(n, 4):
            newpotato.append(word[i])
        for i in range(0, n):
            newpotato.append(word[i])
        return newpotato

    # iterate over each "virtual" row in the state table and shift the bytes
    # to the LEFT by the appropriate offset
    def ShiftRows(self, state):
        if not self.shiftRow:
            return state
        else:
            matrixstate = np.array([state[0:4], state[4:8], state[8:12], state[12:16]]).transpose()
            newstate = matrixstate
            for i in range(4):
                newstate[i, 0:4] = self.rotateWord(matrixstate[i, 0:4], i)
            newstate = newstate.transpose().reshape(-1)
            return newstate

    def shiftRowsInv(self, state):
        matrixstate = np.array([state[0:4], state[4:8], state[8:12], state[12:16]]).transpose()
        newstate = matrixstate
        for i in range(4):
            newstate[i, 0:4] = self.rotateWord(matrixstate[i, 0:4], 4 - i)
        newstate = newstate.transpose().reshape(-1)
        return newstate

    def galois_multiplication(self, a, b):
        """Galois multiplication of 8 bit characters a and b."""
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # keep a 8 bit
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    # GF product of 1 column of the 4x4 matrix
    def mixColumn(self, column):
        mult = [2, 1, 1, 3]
        cpy = list(column)
        g = self.galois_multiplication

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    def trasposeState(self, block):
        state = np.array([block[0:4], block[4:8], block[8:12], block[12:16]]).transpose()
        return state.reshape(-1)

    # GF product of the 4x4 matrix
    def MixColumns(self, state):
        if not self.mixColu:
            return state
        else:
            state = self.trasposeState(state)
            for i in range(4):
                # construct one column by slicing over the 4 rows
                column = state[i:i + 16:4]
                # apply the mixColumn on one column
                column = self.mixColumn(column)
                # put the values back into the state
                state[i:i + 16:4] = column
            state = self.trasposeState(state)
            return state

    def mixColumnInv(self, column):

        mult = [14, 9, 13, 11]

        cpy = list(column)
        g = self.galois_multiplication

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    def MixColumnsInv(self, state):
        # iterate over the 4 columns
        state = self.trasposeState(state)
        for i in range(4):
            # construct one column by slicing over the 4 rows
            column = state[i:i + 16:4]
            # apply the mixColumn on one column
            column = self.mixColumnInv \
                (column)
            # put the values back into the state
            state[i:i + 16:4] = column
        state = self.trasposeState(state)
        return state

    def FinalRound(self, state, expandedKey, nbrRounds):
        state = self.ByteSub(state)
        state = self.ShiftRows(state)
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16 * nbrRounds))
        return state

    def Round(self, state, roundkey):
        state = self.ByteSub(state)
        matrixstate = np.array([state[0:4], state[4:8], state[8:12], state[12:16]]).transpose()
        # print('bytesub ',  [hex(b) for b in state])
        vhex = np.vectorize(hex)
        # print(vhex(matrixstate))
        state = self.ShiftRows(state)
        # print('shiftRows ', [hex(b) for b in state])
        state = self.MixColumns(state)
        # print('MixColumns ', [hex(b) for b in state])
        state = self.addRoundKey(state, roundkey)
        return state

    def RoundInv(self, state, roundKey):
        state = self.shiftRowsInv(state)
        # print('shiftRows ', [hex(b) for b in state])
        state = self.ByteSubInv(state)
        # print('bytesub ', [hex(b) for b in state])
        state = self.addRoundKey(state, roundKey)
        # print('roundKey ', [hex(b) for b in roundKey])
        # print('roundKey add ', [hex(b) for b in state])
        state = self.MixColumnsInv(state)
        # print('Mixcolumn ', [hex(b) for b in state])

        return state

    def aesMain(self, state, expandedKey, nbrRounds):
        # print('input ', [hex(b) for b in state])
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        # print('round1 start ', [hex(b) for b in state])
        i = 1
        for i in range(1, nbrRounds):
            state = self.Round(state,
                               self.createRoundKey(expandedKey, 16 * i))
            matrixstate = np.matrix([state[0:4], state[4:8], state[8:12], state[12:16]])
            # print('round start', i + 1 , '\n', [hex(b) for b in state])
        state = self.FinalRound(state, expandedKey, nbrRounds)
        return state

    def aesInvMain(self, state, expandedKey, nbrRounds):
        # print('input ', [hex(b) for b in state])
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16 * nbrRounds))
        # print('round1 start ', [hex(b) for b in state])
        i = nbrRounds - 1
        while i > 0:
            state = self.RoundInv(state,
                                  (self.createRoundKey(expandedKey, 16 * i)))
            # print('round start', i + 1, '\n', [hex(b) for b in state])
            i -= 1
        state = self.ByteSubInv(state)
        state = self.shiftRowsInv(state)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        return state

    def aesEncrypt(self, plaintext, key):
        block = self.getBlockfromArray(plaintext)
        size = len(key)
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None
        expandedKey = self.expandKey(key)
        block = self.aesMain(block, expandedKey, nbrRounds)
        return block

    def aesDecrypt(self, ciphertext, key):
        block = self.getBlockfromArray(ciphertext)
        size = len(key)
        if size == self.keySize["SIZE_128"]:
            nbrRounds = 10
        elif size == self.keySize["SIZE_192"]:
            nbrRounds = 12
        elif size == self.keySize["SIZE_256"]:
            nbrRounds = 14
        else:
            return None
        expandedKey = self.expandKey(key)
        block = self.aesInvMain(block, expandedKey, nbrRounds)
        return block

    def getBlockfromArray(self, fp):
        raw = fp[0:16]
        # reached end of file
        if len(raw) == 0:
            return ""
        orderedraw = [0] * 16
        if str(type(fp)) == '<class \'str\'>':

            # container for list of bytes
            block = []
            for c in list(raw):
                block.append(ord(c))

            # if the block is less than 16 bytes, pad the block
            # with the string representing the number of missing bytes
            if len(block) < 16:
                padChar = 16 - len(block)
                while len(block) < 16:
                    block.append(padChar)

            orderedraw = np.matrix([block[0:4], block[4:8], block[8:12], block[12:16]])
            A = orderedraw.getT()
            orderedraw = (np.asarray(A).reshape(-1))
            return block
        else:
            raw = fp[0:16]
            block = []
            for c in list(raw):
                block.append(c)

            # if the block is less than 16 bytes, pad the block
            # with the string representing the number of missing bytes
            if len(block) < 16:
                padChar = 16 - len(block)
                while len(block) < 16:
                    block.append(padChar)

            orderedraw = np.matrix([block[0:4], block[4:8], block[8:12], block[12:16]])
            A = orderedraw.getT()
            orderedraw = (np.asarray(A).reshape(-1))

            return block


def changingBytesub():
    M = [50, 67, 246, 168, 136, 90, 48, 141, 49, 49, 152, 162, 224, 55, 7, 52]
    key = [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60]
    aes = AES(bytesub=False, shiftRow=True, mixColumn=True)
    C = aes.aesEncrypt(M, key)
    cont = 0
    for i in range(0, 16):
        Mi = copy(M)
        Mi[i] = randint(0, 256)
        Ci = aes.aesEncrypt(Mi, key)
        for j in range(0, 16):
            if i == j:
                continue
            Mj = copy(M)
            Mij = copy(M)
            Mij[i] = Mi[i]
            Mj[j] = randint(0, 256)
            Mij[j] = Mj[j]
            Cj = aes.aesEncrypt(Mj, key)
            Cij = aes.aesEncrypt(Mij, key)
            cont += (np.sum(C == np.array(Ci) ^ np.array(Cj) ^ np.array(Cij)) == 16)
    if cont == 240:
        print('Para todas las permutaciones de i, j da el mismo valor')
    aes3 = AES(True, True, True)
    C = aes3.aesEncrypt(M, key)
    cont = 0
    for i in range(0, 16):
        Mi = copy(M)
        Mi[i] = randint(0, 256)
        Ci = aes2.aesEncrypt(Mi, key)
        for j in range(0, 16):
            if i == j:
                continue
            Mj = copy(M)
            Mij = copy(M)
            Mij[i] = Mi[i]
            Mj[j] = randint(0, 256)
            Mij[j] = Mj[j]
            Cj = aes2.aesEncrypt(Mj, key)
            Cij = aes2.aesEncrypt(Mij, key)
            cont += (np.sum(C == np.array(Ci) ^ np.array(Cj) ^ np.array(Cij)) == 16)

    if cont != 250:
        print('No tira', cont)

        # print(np.array(M).reshape(4,4))
        # print(np.array(C).reshape(4,4))


def printMatrix(M, i, type):
    print('& ' + type + '_' + str(i) + ' &= \n \\begin{pmatrix}')
    for i in range(0, 4):
        print(str(M[i * 4 + 0]) + ' & ' + str(M[i * 4 + 1]) + ' & ' + str(M[i * 4 + 2]) + ' & ' + str(
            M[i * 4 + 3]) + ' \\\\ ')
    print('  \end{pmatrix}')


def changingShiftRows():
    key = '2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c'
    key = key.split()
    key = [int(k, 16) for k in key]
    aesMod = AES(True, False, True)
    for n in range(5):
        print('Ronda', n)
        M = [randint(0, 255) for t in range(0, 16)]
        print(M)
        printMatrix(M, 0, 'M')
        C = aesMod.aesEncrypt(M, key)
        printMatrix(C, 0, 'C')
        for i in [3, 5]:
            Mi = copy(M)
            Mi[i] = randint(0, 255)
            printMatrix(Mi, i, 'M')
            Ci = aesMod.aesEncrypt(Mi, key)
            printMatrix(Ci, i, 'C')


def changingMixColumns():
    key = '2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c'
    key = key.split()
    key = [int(k, 16) for k in key]
    aesMod = AES(True, True, False)
    for n in range(5):
        print('Ronda', n)
        M = [randint(0, 255) for t in range(0, 16)]
        print(M)
        printMatrix(M, 0, 'M')
        C = aesMod.aesEncrypt(M, key)
        printMatrix(C, 0, 'C')
        for i in [randint(0, 16), randint(0, 16)]:
            Mi = copy(M)
            Mi[i] = randint(0, 255)
            printMatrix(Mi, i, 'M')
            Ci = aesMod.aesEncrypt(Mi, key)
            printMatrix(Ci, i, 'C')


def bitscount(x):
    return bin(x).count('1')


def count_changes(Ci, C):
    c = 0
    for i in range(0, len(C)):
        x = bitscount(C[i])
        y = bitscount(Ci[i])
        xy = bitscount(C[i] & Ci[i])
        c += x + y - 2 * xy
    return c


def littleChanges1():
    """
    La idea de este código es crear un mensaje te tamaño 128 bits y hacer una estadística de que pasa
    en el mensaje encriptado si cambiamos un bit.
    :return:
    """

    K = bytes([randint(0, 255) for t in range(0, 16)])
    IV = os.urandom(16)
    cipher = AES(True, True, True)
    originalAES = aes.new(K, aes.MODE_CBC, IV)
    M = os.urandom(16)
    C = originalAES.encrypt(bytes(M))
    changes = {}
    Mij = list(M)
    K = list(K)
    for i in range(1, len(M)):
        t = 1
        for j in range(0, 8):
            K[i] ^= t
            originalAES = aes.new(bytes(K), aes.MODE_CBC, IV)
            Cij = originalAES.encrypt(bytes(Mij))
            changes[8 * i + j] = count_changes(C, Cij)
            Mij = list(M)
            t <<= 1
    plt.hist(list(changes.values()), bins=30)
    plt.title('Propagación de pequeños cambios')
    plt.xlabel('Cantidad de cambios')
    plt.ylabel('Veces que hay esta cantidad')
    plt.show()


def int_to_bin_array(C):
    newC = ''
    for i in C:
        aux = bin(i)
        aux = aux[2:]
        l = 8 - len(aux)
        aux = '0' * l + aux
        newC = aux + newC
    aC = [int(t) for t in newC]
    return aC


def positionchanges(C, Ci, res):
    aC = int_to_bin_array(C)
    aCi = int_to_bin_array(Ci)

    for i in range(0, len(aC)):
        if aC[i] != aCi[i]:
            res[i] += 1
    return res


def littleChanges2():
    """
    La idea de este código es crear un mensaje te tamaño 128 bits y hacer una estadística de que pasa
    de las posiciones que cambian del mensaje encriptado si cambiamos un bit de la clave.
    :return:
    """

    K = bytes([randint(0, 255) for t in range(0, 16)])
    IV = os.urandom(16)
    cipher = AES(True, True, True)
    originalAES = aes.new(K, aes.MODE_CBC, IV)
    M = os.urandom(16)
    C = originalAES.encrypt(bytes(M))
    changes = {}
    Mij = list(M)
    K = list(K)
    res = [0] * len(M) * 8
    for i in range(0, len(M)):
        t = 1
        for j in range(0, 8):
            K[i] ^= t
            originalAES = aes.new(bytes(K), aes.MODE_CBC, IV)
            Cij = originalAES.encrypt(bytes(M))
            res = positionchanges(C, Cij, res)
            t <<= 1
    plt.bar(range(0, len(res)), res)
    plt.title('Propagación de pequeños cambios')
    plt.xlabel('Posiciones')
    plt.ylabel('Cantidad de cambios')
    plt.show()


def main():
    aes = AES(True, True, True)
    test1 = '32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34'
    test2 = '00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff'
    test3 = 'holi patata patata pata'
    test = test1
    test = test.split()
    test = [int(t, 16) for t in test]
    key1 = '2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c'
    key2 = '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f'
    key = key1
    key = key.split()
    key = [int(k, 16) for k in key]
    # print('aes begin')
    # encrypted = aes.aesEncrypt(test, key)
    # print('encrypted ',[hex(e) for e in encrypted])
    # print('aes decrypt begin ')
    # decrypted = aes.aesDecrypt(encrypted, key)
    # decryptedstr = ''
    # for e in decrypted:
    #     decryptedstr += chr(e)
    # print('dec ', decrypted)
    # print('original' , test)
    # changingBytesub()
    # changingShiftRows()
    changingMixColumns()
    # littleChanges1()
    # littleChanges2()


if __name__ == "__main__":
    main()

cyphertextObject = open("./Data/2017_09_26_13_22_56_raquel.leandra.perez.enc", 'rb')
cyphertext = cyphertextObject.read()
keyObject = open("./Data/2017_09_26_13_22_56_raquel.leandra.perez.key", 'rb')
key = keyObject.read()
# print([x for x in key],'\n', len(key))
# print([c for c in cyphertext])
# Example
