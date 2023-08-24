import os
import zlib

from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory


class Test_Encryption15:
    def test_main(self):
        key = KeyFactory.new("res/encrypted_backup.key")
        db = Database15(key=key, iv=bytes.fromhex("C395EE009CF8B68AC0EA760550F6559C"))
        data = db.encrypt(key, zlib.compress(open("res/msgstore.db", 'rb').read(), 1, 15))
        assert data == open("res/msgstore.db.crypt15", 'rb').read()


