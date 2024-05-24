import os
import zlib

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props
from hashlib import sha512

class TestDecryption:
    def test_decryption15(self):
        key = KeyFactory.new("tests/res/encrypted_backup.key")
        f = open("tests/res/msgstore.db.crypt15",'rb')
        db = DatabaseFactory.from_file(f)
        encrypted = f.read()
        decrypted_db = db.decrypt(key, encrypted)
        decrypted_db = zlib.decompress(decrypted_db)
        new_check = sha512(decrypted_db).digest()
        with open("tests/res/msgstore.db", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check
    
    def test_decryption14(self):
        key = KeyFactory.new("tests/res/key")
        f = open("tests/res/msgstore.db.crypt14",'rb')
        db = DatabaseFactory.from_file(f)
        encrypted = f.read()
        decrypted_db = db.decrypt(key, encrypted)
        decrypted_db = zlib.decompress(decrypted_db)
        new_check = sha512(decrypted_db).digest()
        with open("tests/res/msgstore.db", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check
        
    def test_decryption12(self):
        key = KeyFactory.new("tests/res/key")
        f = open("tests/res/msgstore.db.crypt12",'rb')
        db = DatabaseFactory.from_file(f)
        encrypted = f.read()
        decrypted_db = db.decrypt(key, encrypted)
        decrypted_db = zlib.decompress(decrypted_db)
        new_check = sha512(decrypted_db).digest()
        with open("tests/res/msgstore.db", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert new_check == orig_check