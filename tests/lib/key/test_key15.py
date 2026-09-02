"""
Key15: the crypt15 root key, and the three keys derived from it.
"""

from __future__ import annotations

import pytest

from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

ROOT = bytes.fromhex("6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017")


class TestKey15:
    def test_a_generated_key_is_32_random_bytes(self):
        assert len(Key15().get_root()) == 32
        assert Key15().get_root() != Key15().get_root()

    def test_the_root_key_is_kept_verbatim(self):
        assert Key15(keyarray=ROOT).get_root() == ROOT
        assert Key15(key=ROOT).get_root() == ROOT

    def test_the_cipher_key_is_derived_and_is_not_the_root_key(self):
        key = Key15(keyarray=ROOT)
        assert len(key.get()) == 32
        assert key.get() != key.get_root()

    def test_the_three_derived_keys_all_differ(self):
        key = Key15(keyarray=ROOT)
        derived = {key.get(), key.get_metadata_encryption(), key.get_metadata_authentication()}
        assert len(derived) == 3
        assert all(len(k) == 32 for k in derived)

    def test_a_key_of_the_wrong_length_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="Invalid key length"):
            Key15(key=b"\x00" * 31)
        with pytest.raises(InvalidKeyError, match="expected 32"):
            Key15(keyarray=b"\x00" * 31)

    def test_something_that_is_not_bytes_is_rejected(self):
        # KeyFactory hands over whatever javaobj produced; a list of ints used to get this
        # far and fail much later, inside the HMAC.
        with pytest.raises(InvalidKeyError, match="not a byte array"):
            Key15(keyarray=[0] * 32)

    def test_dump_round_trips_through_the_factory(self, tmp_path):
        path = tmp_path / "encrypted_backup.key"
        Key15(key=ROOT).file_dump(path)
        reloaded = KeyFactory.new(path)
        assert isinstance(reloaded, Key15)
        assert reloaded.get_root() == ROOT

    def test_str_shows_the_root_key(self):
        key = Key15(key=ROOT)
        assert str(key) == f"Key15(key: {ROOT.hex()})"
        assert repr(key) == str(key)

    def test_printing_a_broken_key_reports_instead_of_raising(self):
        # __str__ is called from log formatting and from debuggers, so it has to survive a
        # key that should not exist -- a second traceback from inside the first helps nobody.
        key = Key15(key=ROOT)
        key._Key15__key = "not bytes"
        assert str(key).startswith("Exception printing key: ")
