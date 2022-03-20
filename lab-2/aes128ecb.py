from Crypto.Cipher import AES
import random
import string
import functools


def random_text(_block_size):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(_block_size))


def init():
    global key, salt, cipher

    key = random_text(16)
    salt = random_text(16)
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)


def pad(text):
    if len(text) % 16 != 0:
        text = text + '0' * (16 - len(text) % 16)
    return text


def encrypt(text):
    text += salt
    text = pad(text)
    line = cipher.encrypt(text.encode("utf8")).hex()
    return [line[i:i + 2] for i in range(0, len(line), 2)]


if __name__ == "__main__":
    init()
    print('Initial salt: ', salt)

    letters = string.ascii_letters
    part = '@@@@@@@@@@@@@@@'
    cSalt = ''
    pos = 0

    while len(cSalt) < 16:
        for letter in letters:
            res = encrypt(part[:len(part) - pos] + cSalt + letter + part[:len(part) - pos])

            if functools.reduce(lambda x, y: x and y, map(lambda p, q: p == q,res[:16],res[16:32]), True):
                cSalt += letter
                pos += 1
                break

        print(cSalt)

print('Salt is: ', cSalt)