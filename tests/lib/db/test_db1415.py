"""
Database14 and Database15 share everything but the header they write, so they are exercised
together: the IV check, the multifile-backup branch of decrypt, and get_iv.
"""

import io
import zlib
from hashlib import sha512

import pytest

from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import IntegrityError
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

CASES = [
    pytest.param(Database15, "tests/res/encrypted_backup.key", "tests/res/msgstore.db.crypt15", id="crypt15"),
    pytest.param(Database14, "tests/res/key", "tests/res/msgstore.db.crypt14", id="crypt14"),
]


def read(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def as_stream(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(io.BytesIO(data))


@pytest.mark.parametrize("cls, keyfile, backup", CASES)
class TestHeaderConstruction:
    def test_an_iv_of_the_wrong_length_is_rejected(self, cls, keyfile, backup):
        with pytest.raises(IntegrityError, match="15 bytes long"):
            cls(iv=b'\x00' * 15)

    def test_an_iv_is_generated_when_not_given(self, cls, keyfile, backup):
        assert cls().get_iv() != cls().get_iv()
        assert len(cls().get_iv()) == 16

    def test_get_iv_returns_the_iv_it_was_built_with(self, cls, keyfile, backup):
        iv = bytes(range(16))
        assert cls(iv=iv).get_iv() == iv


@pytest.mark.parametrize("cls, keyfile, backup", CASES)
class TestMultifileBackups:
    """
    A multifile backup has no trailing md5 of the file; the tag sits where the checksum
    would be. decrypt() detects that by the checksum not matching and shifts everything by
    16 bytes -- so the last 16 bytes of ciphertext must still end up in the plaintext.
    """

    def test_a_backup_without_a_checksum_still_decrypts_in_full(self, cls, keyfile, backup):
        key = KeyFactory.new(keyfile)
        stream = as_stream(read(backup)[:-16])
        db = DatabaseFactory.from_file(stream)
        assert isinstance(db, cls)

        decrypted = zlib.decompress(db.decrypt(key, stream.read()))

        assert sha512(decrypted).digest() == sha512(read("tests/res/msgstore.db")).digest()

    def test_a_corrupted_multifile_backup_is_still_caught(self, cls, keyfile, backup):
        key = KeyFactory.new(keyfile)
        data = bytearray(read(backup)[:-16])
        data[-40] ^= 0xFF
        stream = as_stream(bytes(data))
        db = DatabaseFactory.from_file(stream)

        with pytest.raises(IntegrityError, match="Authentication tag mismatch"):
            db.decrypt(key, stream.read())


class TestStr:
    def test_database15(self):
        assert str(Database15()) == "Database15"

    def test_database14_shows_its_iv(self):
        # It used to print Database12's fields, none of which Database14 has, so any attempt
        # to print one died with an AttributeError.
        iv = bytes(range(16))
        assert str(Database14(iv=iv)) == "Database14(iv: {})".format(iv.hex())
