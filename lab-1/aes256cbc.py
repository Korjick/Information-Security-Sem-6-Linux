import random
import string

from Crypto.Cipher import AES


class AES256CBC:
    key_size = 32

    @staticmethod
    def encryptBase(text, key):
        return AES256CBC._encrypt(text, key)

    @staticmethod
    def encryptLinear(text, key):
        return AES256CBC._encrypt(text, key, True)

    @staticmethod
    def decryptBase(raw, key):
        return AES256CBC._decrypt(raw, key)

    @staticmethod
    def decryptLinear(raw):
        return AES256CBC._decrypt(raw, sew_key=True)

    @classmethod
    def random_text(cls, _block_size):
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for _ in range(_block_size))

    @classmethod
    def _add_padding(cls, bytes_arr):
        count = AES256CBC.key_size - (len(bytes_arr) % AES256CBC.key_size)
        return bytes_arr + (bytes('\x05', 'utf-8') * count)

    @classmethod
    def _remove_padding(cls, bytes_arr):
        try:
            return bytes_arr.replace(b'\x05', b'').decode('utf-8')
        except:
            return bytes_arr.replace(b'\x05', b'')

    @classmethod
    def _encrypt(cls, text, key, sew_key=False):
        key = bytes(key, 'utf-8')
        cipher = AES.new(key, AES.MODE_CBC)
        if sew_key:
            encrypted = cipher.encrypt(AES256CBC._add_padding(bytes(text, 'utf-8')))
            val = random.randint(0, len(encrypted) - 1)
            encrypted = encrypted[:val] + key + encrypted[val:]
        else:
            encrypted = cipher.encrypt(AES256CBC._add_padding(bytes(text, 'utf-8')))
        return cipher.iv + encrypted

    @classmethod
    def _decrypt(cls, raw, key=None, sew_key=False):
        iv = raw[:AES.block_size]
        block = raw[AES.block_size:]
        if sew_key:
            res = {}
            for i in range(len(block) - AES256CBC.key_size):
                key = block[i:AES256CBC.key_size + i]
                value = block[:i] + block[AES256CBC.key_size + i:]
                cipher = AES.new(key, AES.MODE_CBC, iv)

                data = {'key': key, 'encoded:': value}
                value = AES256CBC._remove_padding(cipher.decrypt(value))
                res[value] = data
        else:
            key = bytes(key, 'utf-8')
            cipher = AES.new(key, AES.MODE_CBC, iv)
            res = {AES256CBC._remove_padding(cipher.decrypt(block)): {'key: ': key, 'encoded: ': block}}
        return res


if __name__ == "__main__":
    key = AES256CBC.random_text(32)
    txt = 'Hello from future, dear hackers XD'
    enc = AES256CBC.encryptLinear(txt, key)
    res = AES256CBC.decryptLinear(enc)
    if txt in res:
        print('For word: {txt} - we know: '.format(txt=txt), res[txt])

