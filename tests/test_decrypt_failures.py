"""
The failure paths of decryption.

Until these existed the library logged an error and carried on: a backup whose
authentication tag did not match still had its plaintext returned to the caller, and an
unusable key file surfaced later as an AttributeError on None.
"""

import io
import zlib

import pytest

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import HeaderError, IntegrityError, InvalidKeyError
from wa_crypt_tools.lib.key.keyfactory import KeyFactory


def as_stream(data: bytes) -> io.BufferedReader:
    """DatabaseFactory needs a buffered stream: it peeks at the feature-table flag."""
    return io.BufferedReader(io.BytesIO(data))


def read(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


class TestDecryptionFailures:
    def test_corrupted_ciphertext_raises_and_carries_the_plaintext(self):
        key = KeyFactory.new("tests/res/encrypted_backup.key")
        data = bytearray(read("tests/res/msgstore.db.crypt15"))
        # Flip a bit in the ciphertext, before the tag and the checksum at the end.
        data[-40] ^= 0xFF
        stream = as_stream(bytes(data))
        db = DatabaseFactory.from_file(stream)

        with pytest.raises(IntegrityError) as excinfo:
            db.decrypt(key, stream.read())

        # --force writes this out instead of decrypting a second time, so it has to be the
        # real plaintext -- here, the zlib stream the backup compresses to -- and not an
        # empty or truncated stand-in.
        salvaged = excinfo.value.data
        assert salvaged is not None
        assert salvaged[:2] in (b'x\x01', b'PK')
        assert len(salvaged) > len(data) // 2

    def test_wrong_key_raises(self):
        # The crypt14 key against a crypt15 backup.
        key = KeyFactory.new("tests/res/key")
        stream = as_stream(read("tests/res/msgstore.db.crypt15"))
        db = DatabaseFactory.from_file(stream)

        with pytest.raises(IntegrityError):
            db.decrypt(key, stream.read())

    def test_forced_plaintext_is_not_the_real_database(self):
        """What --force hands back is real plaintext, just unauthenticated."""
        key = KeyFactory.new("tests/res/encrypted_backup.key")
        data = bytearray(read("tests/res/msgstore.db.crypt15"))
        data[-40] ^= 0xFF
        stream = as_stream(bytes(data))
        db = DatabaseFactory.from_file(stream)

        with pytest.raises(IntegrityError) as excinfo:
            db.decrypt(key, stream.read())

        # It still decompresses -- the corruption is one byte near the end -- but it is not
        # the reference database, which is the whole reason the tag is checked.
        salvaged = zlib.decompressobj().decompress(excinfo.value.data)
        assert salvaged != read("tests/res/msgstore.db")

    def test_truncated_header_raises(self):
        with pytest.raises((HeaderError, IntegrityError)):
            DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")[:3]))

    def test_a_file_that_is_not_a_backup_raises(self):
        # Falls through to the crypt12 branch, which has no magic of its own; the cipher
        # version is what tells a real crypt12 apart from any other file.
        with pytest.raises(IntegrityError):
            DatabaseFactory.from_file(as_stream(read("tests/res/test.json")))

    def test_a_zip_is_not_a_backup_either(self):
        with pytest.raises(IntegrityError):
            DatabaseFactory.from_file(as_stream(read("tests/res/test9.zip")))


class TestKeyFailures:
    def test_a_file_that_is_not_a_key_raises(self):
        with pytest.raises(InvalidKeyError):
            KeyFactory.new("tests/res/test.json")

    def test_hex_string_of_the_wrong_length_raises(self):
        with pytest.raises(InvalidKeyError):
            KeyFactory.new("0123456789abcdef")

    def test_non_hex_string_of_the_right_length_raises(self):
        # This used to die with "TypeError: object of type 'NoneType' has no len()".
        with pytest.raises(InvalidKeyError):
            KeyFactory.new("z" * 64)

    def test_a_missing_file_is_tried_as_a_hex_key(self):
        with pytest.raises(InvalidKeyError):
            KeyFactory.new("tests/res/there-is-no-such-file")


class TestCrypt12Fallback:
    def test_a_real_crypt12_is_still_recognised(self):
        """
        DatabaseFactory picks crypt12 by failing to parse a crypt14/15 header. That control
        flow is what the exception refactor most easily breaks, so assert the type directly
        rather than only round-tripping the bytes.
        """
        db = DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt12")))
        assert isinstance(db, Database12)
