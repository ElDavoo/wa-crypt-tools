"""
Database12: the legacy fixed-offset header, which is the only one built from a key.

Its header is not a protobuf, so nothing validates it for us; the checks in __init__ are the
validation.
"""

import io
import zlib
from hashlib import sha512

import pytest

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.errors import IntegrityError, InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props

IV = bytes.fromhex("F4E9A6DC0B6F0D8986AF6C7180F02356")


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def key() -> Key14:
    return KeyFactory.new("tests/res/key")


class TestDatabase12FromAHeaderAndAKey:
    """The header is read off the stream and checked field by field against the key."""

    def test_a_matching_key_is_accepted_and_the_iv_is_read(self):
        stream = io.BytesIO(read("tests/res/msgstore.db.crypt12"))
        db = Database12(key=key(), encrypted=stream)
        assert db.cipher_version == C.SUPPORTED_CIPHER_VERSION
        assert db.get_iv() == IV
        # The stream is left at the start of the ciphertext, which is what callers rely on.
        assert stream.tell() == 67
        decrypted = zlib.decompress(db.decrypt(key(), stream.read()))
        assert sha512(decrypted).digest() == sha512(read("tests/res/msgstore.db")).digest()

    @pytest.mark.parametrize(
        "offset, message",
        [
            pytest.param(0, "Cipher version mismatch", id="cipher-version"),
            pytest.param(2, "Key version mismatch", id="key-version"),
            pytest.param(3, "Server salt mismatch", id="server-salt"),
            pytest.param(35, "Google ID mismatch", id="google-id"),
        ],
    )
    def test_a_header_that_does_not_match_the_key_is_rejected(self, offset, message):
        data = bytearray(read("tests/res/msgstore.db.crypt12"))
        data[offset] ^= 0xFF
        with pytest.raises(IntegrityError, match=message):
            Database12(key=key(), encrypted=io.BytesIO(bytes(data)))


class TestDatabase12FromAKey:
    """What waencrypt does: the header is generated from the key, not read."""

    def test_every_field_comes_from_the_key(self):
        k = key()
        db = Database12(key=k, iv=IV)
        assert db.cipher_version == k.get_cipher_version()
        assert db.key_version == k.get_key_version()
        assert db.serversalt == k.get_serversalt()
        assert db.googleid == k.get_googleid()
        assert db.get_iv() == IV

    def test_the_iv_is_generated_when_not_given(self):
        assert Database12(key=key()).get_iv() != Database12(key=key()).get_iv()

    def test_str_names_every_header_field(self):
        string = str(Database12(key=key(), iv=IV))
        for field in ("cipher_version", "key_version", "serversalt", "googleid", "iv"):
            assert field in string


class TestDatabase12FromParameters:
    def test_the_defaults_are_the_supported_versions(self):
        db = Database12()
        assert db.cipher_version == C.SUPPORTED_CIPHER_VERSION
        assert db.key_version == C.SUPPORTED_KEY_VERSIONS[-1]
        assert len(db.serversalt) == 32
        assert len(db.googleid) == 16
        assert len(db.get_iv()) == 16

    def test_supplied_parameters_are_kept(self):
        salt, googleid = bytes(range(32)), bytes(range(16))
        db = Database12(cipher_version=b"\x00\x01", key_version=b"\x01", serversalt=salt, googleid=googleid, iv=IV)
        assert db.key_version == b"\x01"
        assert db.serversalt == salt
        assert db.googleid == googleid
        assert db.get_iv() == IV

    def test_an_unsupported_cipher_version_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="cipher version"):
            Database12(cipher_version=b"\x00\x02")

    def test_an_unsupported_key_version_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="key version"):
            Database12(key_version=b"\x09")


class TestDatabase12Decryption:
    def test_a_corrupted_backup_raises_and_carries_the_plaintext(self):
        data = bytearray(read("tests/res/msgstore.db.crypt12"))
        data[-60] ^= 0xFF
        stream = io.BytesIO(bytes(data))
        db = Database12(key=key(), encrypted=stream)

        with pytest.raises(IntegrityError, match="Authentication tag mismatch"):
            db.decrypt(key(), stream.read())

    def test_a_footer_without_a_phone_number_is_only_complained_about(self, caplog):
        import logging

        # The last four bytes are "--67" in a real backup. They are not used for anything
        # cryptographic, so a backup missing them still has to decrypt.
        original = read("tests/res/msgstore.db.crypt12")
        data = original[:-4] + b"ABCD"
        stream = io.BytesIO(data)
        db = Database12(key=key(), encrypted=stream)
        with caplog.at_level(logging.ERROR, logger="wa_crypt_tools.lib.db.db12"):
            decrypted = db.decrypt(key(), stream.read())
        assert "phone number end is not 2 characters long" in caplog.text
        assert zlib.decompress(decrypted)[:15] == b"SQLite format 3"


class TestDatabase12Encryption:
    def test_a_jid_that_is_not_two_characters_is_complained_about(self, caplog):
        import logging

        db = Database12(key=key(), iv=IV)
        with caplog.at_level(logging.ERROR, logger="wa_crypt_tools.lib.db.db12"):
            out = db.encrypt(key(), Props(jid="1234", features=None), zlib.compress(b"x" * 64, level=1))
        assert "phone number end is not 2 characters long" in caplog.text
        assert out.endswith(b"--1234")
