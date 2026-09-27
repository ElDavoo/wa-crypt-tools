"""
KeyFactory: a path or a raw hex string in, a Key14 or a Key15 out.

The version is guessed from the length of the deserialized payload, so the lengths are the
whole contract.
"""

from __future__ import annotations

import pytest
from javaobj import JavaObjectMarshaller

from tests.utils.utils import requires_ocr
from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.utils import create_jba

ROOT = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"


class TestFromFile:
    def test_a_131_byte_payload_is_a_crypt14_key(self):
        assert isinstance(KeyFactory.from_file("tests/res/key"), Key14)

    def test_a_32_byte_payload_is_a_crypt15_key(self):
        key = KeyFactory.from_file("tests/res/encrypted_backup.key")
        assert isinstance(key, Key15)
        assert key.get_root().hex() == ROOT

    def test_any_other_length_is_rejected_by_length(self, tmp_path):
        # A well-formed Java byte[] of the wrong size: the deserialization succeeds, so this
        # is the only check that catches it.
        path = tmp_path / "key"
        path.write_bytes(JavaObjectMarshaller().dump(create_jba(b"\x00" * 64)))
        with pytest.raises(InvalidKeyError, match="64 bytes long"):
            KeyFactory.from_file(path)

    def test_a_file_that_is_not_a_java_object_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="not a valid Java object"):
            KeyFactory.from_file("tests/res/test.json")

    def test_a_missing_file_raises_oserror_so_new_can_retry_it_as_hex(self):
        # new() distinguishes the two by the exception type; an InvalidKeyError here would
        # make an unreadable key file get retried as a hex string and reported wrongly.
        with pytest.raises(OSError):
            KeyFactory.from_file("tests/res/there-is-no-such-file")


class TestFromHex:
    def test_a_64_character_hex_string_is_a_crypt15_key(self):
        key = KeyFactory.from_hex(ROOT)
        assert isinstance(key, Key15)
        assert key.get_root() == bytes.fromhex(ROOT)

    def test_none_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="not 0 characters"):
            KeyFactory.from_hex(None)

    def test_the_wrong_length_is_rejected(self):
        with pytest.raises(InvalidKeyError, match="not 63 characters"):
            KeyFactory.from_hex(ROOT[:-1])


class TestNew:
    def test_a_path_is_read_as_a_file(self):
        assert isinstance(KeyFactory.new("tests/res/key"), Key14)

    def test_something_that_is_not_a_path_is_read_as_hex(self):
        assert KeyFactory.new(ROOT).get_root() == bytes.fromhex(ROOT)

    def test_an_unreadable_key_file_is_not_retried_as_hex(self, tmp_path):
        # The user gets "the keyfile is not a valid Java object", not the hex-string advice
        # for a string they never typed.
        path = tmp_path / "key"
        path.write_bytes(b"this is not a java object")
        with pytest.raises(InvalidKeyError, match="not a valid Java object"):
            KeyFactory.new(path)


class TestFromImage:
    """A screenshot goes in where a key file goes, and comes out a Key15."""

    SYNTHETIC = "tests/res/key-screenshot-synthetic.png"
    #: What that screenshot spells out -- the same key as tests/res/encrypted_backup.key,
    #: which is what lets it decrypt the fixture backup.
    SHOWN = ROOT

    def test_a_screenshot_is_read_as_a_key(self):
        requires_ocr()
        key = KeyFactory.new(self.SYNTHETIC)
        assert isinstance(key, Key15)
        assert key.get_root().hex() == self.SHOWN

    def test_a_key_file_is_still_read_as_a_key_file(self):
        # The image sniff runs before anything else in new(), so this is the check that it
        # does not shadow the path every existing caller takes. No OCR needed to prove it.
        assert isinstance(KeyFactory.new("tests/res/key"), Key14)
        assert isinstance(KeyFactory.new("tests/res/encrypted_backup.key"), Key15)

    def test_a_backup_is_not_mistaken_for_a_screenshot(self):
        with pytest.raises(InvalidKeyError, match="not a valid Java object"):
            KeyFactory.new("tests/res/msgstore.db.crypt15")
