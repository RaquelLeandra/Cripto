"""
Código auxiliar para el examen parcial
"""
import numpy as np

def galois_multiplication( a, b):
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


def mixColumn(column):
    mult = [2, 1, 1, 3]
    cpy = list(column)
    g = galois_multiplication

    column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
    column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
    column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
    column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
    return column


def trasposeState( block):
    state = np.array([block[0:4], block[4:8], block[8:12], block[12:16]]).transpose()
    return state.reshape(-1)

    # GF product of the 4x4 matrix


def MixColumns(state):

    state = trasposeState(state)
    for i in range(4):
        # construct one column by slicing over the 4 rows
        column = state[i:i + 16:4]
        # apply the mixColumn on one column
        column = mixColumn(column)
        # put the values back into the state
        state[i:i + 16:4] = column
    state = trasposeState(state)
    return state

s = [0x1C] * 16

print(s)

print(MixColumns(s))