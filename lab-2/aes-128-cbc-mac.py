import itertools
import numpy as np

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor


def getLabel(b_text):
    return AES.new(b"YELLOW SUBMARINE", AES.MODE_CBC, b'\x00' * 16).encrypt(pad(b_text))[-16:]


def pad(b_text):
    char = 16 - len(b_text) % 16
    return b_text + bytes([char] * char)


if __name__ == "__main__":
    begin = b'alert("Hello world!");'
    bHash = getLabel(begin)
    print('Original hash: ', bHash.hex())

    hack = b'alert("You are pwned!");'
    iterationCount = 16 if (7 - len(hack)) % 16 == 0 else (7 - len(hack)) % 16
    for _ in itertools.permutations(range(32, 127), iterationCount):
        sHack = hack + bytes(_)
        hHash = getLabel(sHack)
        pHack = pad(sHack)

        collision = pHack + strxor(begin[:16], hHash) + begin[16:]
        viceVersa = collision[-len(begin):-len(begin) + 16]

        if all(32 <= c < 127 for c in viceVersa):
            print(collision)
            exit(0)
