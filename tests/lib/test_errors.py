from __future__ import annotations

from wa_crypt_tools.lib.errors import (
    DecryptionError,
    HeaderError,
    IntegrityError,
    InvalidKeyError,
    WaCryptError,
)


class TestErrors:
    def test_everything_is_a_valueerror(self):
        # The library raised bare ValueError before these classes existed; callers that
        # already catch it must keep working.
        for cls in (WaCryptError, InvalidKeyError, HeaderError, DecryptionError, IntegrityError):
            assert issubclass(cls, ValueError)
            assert issubclass(cls, WaCryptError)

    def test_not_an_oserror(self):
        # KeyFactory.new catches OSError to fall back from a key file to a hex string.
        # A library error must not be mistaken for a file that could not be opened.
        for cls in (InvalidKeyError, HeaderError, DecryptionError, IntegrityError):
            assert not issubclass(cls, OSError)

    def test_integrity_error_carries_data(self):
        error = IntegrityError("bad tag", data=b"plaintext")
        assert error.data == b"plaintext"
        assert "bad tag" in str(error)

    def test_integrity_error_data_is_optional(self):
        assert IntegrityError("nothing to hand back").data is None
