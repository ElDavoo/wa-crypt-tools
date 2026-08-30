"""
Key14: the crypt12/14 key, built either from a 131-byte keyfile payload or from parameters.

The parameter path is what wacreatekey uses, and every one of its validations is the only
thing standing between a typo and a key file that silently decrypts nothing.
"""

from hashlib import sha256

import pytest

from wa_crypt_tools.lib.errors import IntegrityError, InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

SALT = bytes(range(32))
GOOGLEID = bytes(range(16))
KEY = bytes(range(32, 64))


def keyarray(*, cipher_version=b'\x00\x01', key_version=b'\x03', serversalt=SALT,
             googleid=GOOGLEID, hashedgoogleid=None, padding=b'\x00' * 16, key=KEY) -> bytes:
    """The 131-byte payload a crypt14 key file deserializes to."""
    if hashedgoogleid is None:
        hashedgoogleid = sha256(googleid).digest()
    return cipher_version + key_version + serversalt + googleid + hashedgoogleid + padding + key


class TestKey14FromParameters:
    def test_the_defaults_are_supported_versions(self):
        key = Key14()
        assert key.get_cipher_version() == b'\x00\x01'
        assert key.get_key_version() == b'\x03'
        # Salt, google id and key are random, so only their shape can be asserted.
        assert len(key.get_serversalt()) == 32
        assert len(key.get_googleid()) == 16
        assert len(key.get()) == 32

    def test_two_generated_keys_differ(self):
        assert Key14().get() != Key14().get()

    def test_supplied_parameters_are_kept(self):
        key = Key14(key=KEY, serversalt=SALT, googleid=GOOGLEID,
                    key_version=b'\x01', cipher_version=b'\x00\x01')
        assert key.get() == KEY
        assert key.get_serversalt() == SALT
        assert key.get_googleid() == GOOGLEID
        assert key.get_key_version() == b'\x01'

    @pytest.mark.parametrize("kwargs", [
        {"cipher_version": b'\x00\x02'},
        {"key_version": b'\x04'},
        {"serversalt": b'\x00' * 31},
        {"googleid": b'\x00' * 15},
        {"hashedgoogleid": b'\x00' * 31},
        {"iv": b'\x00' * 15},
        {"key": b'\x00' * 31},
    ], ids=lambda k: next(iter(k)))
    def test_a_field_of_the_wrong_shape_is_rejected(self, kwargs):
        with pytest.raises(InvalidKeyError):
            Key14(**kwargs)

    def test_the_hashed_google_id_defaults_to_the_hash_of_the_google_id(self):
        # Not exposed by a getter, so go through the dump, where it sits at offset 51.
        key = Key14(googleid=GOOGLEID, serversalt=SALT, key=KEY)
        assert sha256(GOOGLEID).digest() in key.dump()

    def test_a_supplied_hashed_google_id_is_used_as_is(self):
        # It is allowed -- some key files in the wild have one that does not match -- but
        # the user is told, because it makes the key unverifiable.
        bogus = b'\xAA' * 32
        key = Key14(googleid=GOOGLEID, hashedgoogleid=bogus, serversalt=SALT, key=KEY)
        assert bogus in key.dump()

    def test_a_non_zero_iv_is_warned_about_but_accepted(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="wa_crypt_tools.lib.key.key14"):
            Key14(iv=b'\x01' * 16, serversalt=SALT, googleid=GOOGLEID, key=KEY)
        assert "IV should be empty" in caplog.text


class TestKey14FromAKeyfile:
    def test_a_valid_payload_is_parsed_field_by_field(self):
        key = Key14(keyarray=keyarray())
        assert key.get_cipher_version() == b'\x00\x01'
        assert key.get_key_version() == b'\x03'
        assert key.get_serversalt() == SALT
        assert key.get_googleid() == GOOGLEID
        assert key.get() == KEY

    def test_every_problem_is_reported_at_once(self):
        # The key is parsed whole before raising, so --force has something usable and the
        # user sees all four complaints in one run instead of one per attempt.
        bad = keyarray(cipher_version=b'\x00\x02', key_version=b'\x09',
                       hashedgoogleid=b'\xAA' * 32, padding=b'\x01' * 16)
        with pytest.raises(IntegrityError) as excinfo:
            Key14(keyarray=bad)
        message = str(excinfo.value)
        assert "Unsupported cipher version" in message
        assert "Unsupported key version" in message
        assert "Invalid SHA-256 of salt" in message
        assert "IV is not zeroed out" in message

    def test_the_error_carries_the_whole_key(self):
        with pytest.raises(IntegrityError) as excinfo:
            Key14(keyarray=keyarray(padding=b'\x01' * 16))
        salvaged = excinfo.value.data
        assert isinstance(salvaged, Key14)
        assert salvaged.get() == KEY
        assert salvaged.get_serversalt() == SALT


class TestKey14Serialization:
    def test_dump_round_trips_through_the_factory(self, tmp_path):
        key = Key14(key=KEY, serversalt=SALT, googleid=GOOGLEID, key_version=b'\x02')
        path = tmp_path / "key"
        key.file_dump(path)
        reloaded = KeyFactory.new(path)
        assert isinstance(reloaded, Key14)
        assert reloaded.get() == key.get()
        assert reloaded.get_serversalt() == key.get_serversalt()
        assert reloaded.get_googleid() == key.get_googleid()
        assert reloaded.get_key_version() == key.get_key_version()

    def test_str_shows_every_field_in_hex(self):
        key = Key14(key=KEY, serversalt=SALT, googleid=GOOGLEID, key_version=b'\x02')
        string = str(key)
        assert string.startswith("Key14(") and string.endswith(")")
        for field in (KEY, SALT, GOOGLEID, b'\x02', b'\x00\x01'):
            assert field.hex() in string
        assert repr(key) == string
