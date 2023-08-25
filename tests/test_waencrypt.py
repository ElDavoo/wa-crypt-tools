import os
import zlib

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props
from hashlib import sha512

class Test_Encryption:
    def test_encryption15(self):
        key = KeyFactory.new("res/encrypted_backup.key")
        props = Props(wa_version="2.22.5.13", jid="67", features=[5,7,8,13,14,19,22,25,28,30,31,32,36,37], max_feature=37)
        db = Database15(key=key, iv=bytes.fromhex("C395EE009CF8B68AC0EA760550F6559C"))
        data = db.encrypt(key, props, zlib.compress(open("res/msgstore.db", 'rb').read(), 1, 15))
        new_check = sha512(data).digest()
        with open("res/msgstore-new.db.crypt15", 'wb') as f:
            f.write(data)
        with open("res/msgstore.db.crypt15", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check

    def test_encryption14(self):
        key = KeyFactory.new("res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=[5,7,8,13,14,19,22,25,28,30,31,32,36,37], max_feature=37)
        db = Database14(key=key, iv=bytes.fromhex("EA53CEAE36ECAB50BC331AEB62491625"))
        data = db.encrypt(key, props, zlib.compress(open("res/msgstore.db", 'rb').read(), 1, 15))
        new_check = sha512(data).digest()
        with open("res/msgstore-new.db.crypt14", 'wb') as f:
            f.write(data)
        with open("res/msgstore.db.crypt14", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check

    def test_encryption14_noprops(self):
        key = KeyFactory.new("res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=None)
        db = Database14(key=key, iv=bytes.fromhex("EA53CEAE36ECAB50BC331AEB62491625"))
        data = db.encrypt(key, props, zlib.compress(open("res/msgstore.db", 'rb').read(), 1, 15))
        new_check = sha512(data).digest()
        with open("res/msgstore-new.db.crypt14", 'wb') as f:
            f.write(data)
        with open("res/msgstore-noprops.db.crypt14", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check

    def test_encryption12(self):
        key = KeyFactory.new("res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=None)
        db = Database12(key=key, iv=bytes.fromhex("F4E9A6DC0B6F0D8986AF6C7180F02356"))
        data = db.encrypt(key, props, zlib.compress(open("res/msgstore.db", 'rb').read(), 1, 15))
        new_check = sha512(data).digest()
        with open("res/msgstore-new.db.crypt12", 'wb') as f:
            f.write(data)
        with open("res/msgstore.db.crypt12", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check