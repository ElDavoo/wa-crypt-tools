import io
import zlib

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props
from hashlib import sha512

# zlib-ng (used by CPython 3.14+ on Windows) produces different compressed
# bytes than classic zlib, so the encrypted output can only be compared
# byte-by-byte with the reference files when classic zlib is in use.
CLASSIC_ZLIB = ("zlib-ng" not in zlib.ZLIB_VERSION
                and "zlib-ng" not in zlib.ZLIB_RUNTIME_VERSION)


def decrypt_roundtrip(key, data: bytes) -> bytes:
    """Decrypts and decompresses an in-memory encrypted database."""
    encrypted = io.BufferedReader(io.BytesIO(data))
    db = DatabaseFactory.from_file(encrypted)
    return zlib.decompress(db.decrypt(key, encrypted.read()))


class TestEncryption:
    def test_encryption15(self):
        key = KeyFactory.new("tests/res/encrypted_backup.key")
        props = Props(wa_version="2.22.5.13", jid="67", features=[5, 7, 8, 13, 14, 19, 22, 25, 28, 30, 31, 32, 36, 37],
                      max_feature=37)
        db = Database15(key=key, iv=bytes.fromhex("C395EE009CF8B68AC0EA760550F6559C"))
        with open("tests/res/msgstore.db", 'rb') as f:
            orig = f.read()
        data = db.encrypt(
            key,
            props,
            zlib.compress(orig, level=1)
        )
        if CLASSIC_ZLIB:
            with open("tests/res/msgstore.db.crypt15", 'rb') as f:
                assert sha512(data).digest() == sha512(f.read()).digest()
        assert sha512(decrypt_roundtrip(key, data)).digest() == sha512(orig).digest()

    def test_encryption14(self):
        key = KeyFactory.new("tests/res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=[5, 7, 8, 13, 14, 19, 22, 25, 28, 30, 31, 32, 36, 37],
                      max_feature=37)
        db = Database14(key=key, iv=bytes.fromhex("EA53CEAE36ECAB50BC331AEB62491625"))
        with open("tests/res/msgstore.db", 'rb') as f:
            orig = f.read()
        data = db.encrypt(
            key,
            props,
            zlib.compress(orig, level=1)
        )
        if CLASSIC_ZLIB:
            with open("tests/res/msgstore.db.crypt14", 'rb') as f:
                assert sha512(data).digest() == sha512(f.read()).digest()
        assert sha512(decrypt_roundtrip(key, data)).digest() == sha512(orig).digest()

    def test_encryption14_noexpiry(self):
        key = KeyFactory.new("tests/res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=None)
        db = Database14(key=key, iv=bytes.fromhex("EA53CEAE36ECAB50BC331AEB62491625"))
        with open("tests/res/msgstore.db", 'rb') as f:
            orig = f.read()
        data = db.encrypt(
            key,
            props,
            zlib.compress(orig, level=1)
        )
        if CLASSIC_ZLIB:
            with open("tests/res/msgstore-noexpiry.db.crypt14", 'rb') as f:
                assert sha512(data).digest() == sha512(f.read()).digest()
        assert sha512(decrypt_roundtrip(key, data)).digest() == sha512(orig).digest()

    def test_encryption12(self):
        key = KeyFactory.new("tests/res/key")
        props = Props(wa_version="2.22.5.13", jid="67", features=None)
        db = Database12(key=key, iv=bytes.fromhex("F4E9A6DC0B6F0D8986AF6C7180F02356"))
        with open("tests/res/msgstore.db", 'rb') as f:
            orig = f.read()
        data = db.encrypt(
            key,
            props,
            zlib.compress(orig, level=1)
        )
        if CLASSIC_ZLIB:
            with open("tests/res/msgstore.db.crypt12", 'rb') as f:
                assert sha512(data).digest() == sha512(f.read()).digest()
        assert sha512(decrypt_roundtrip(key, data)).digest() == sha512(orig).digest()
