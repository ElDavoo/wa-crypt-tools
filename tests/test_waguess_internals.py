"""
The parts of waguess that can be reached without brute-forcing a backup.

The search itself is exercised end to end in tests/tools-invocation/test_waguess.py, which
runs it over a real backup in each of the three formats and takes about twenty seconds a
time. What is here needs neither a backup nor a subprocess: the order the offsets are tried
in, the checks that happen before a byte is read, and the failures of the write-out that
follows a successful search -- which the end-to-end tests, by definition, never see.
"""

from __future__ import annotations

import io
import logging
import zlib
from types import SimpleNamespace

import pytest

from wa_crypt_tools import waguess
from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.errors import DecryptionError, WaCryptError


def _args(*, iv_offset: int = C.DEFAULT_IV_OFFSET, data_offset: int = C.DEFAULT_DATA_OFFSET) -> SimpleNamespace:
    """Arguments that would be valid but for the offsets: nothing past them is reached."""
    return SimpleNamespace(
        keyfile="tests/res/encrypted_backup.key",
        encrypted=None,
        decrypted=None,
        iv_offset=iv_offset,
        data_offset=data_offset,
    )


class TestOscillate:
    """
    The order candidate offsets are tried in: the given one first, then outwards from it.

    Which matters for how long a search takes and not at all for what it finds, so what is
    pinned here is that the closest values really do come first and that the whole range is
    covered exactly once.
    """

    def test_the_documented_example(self):
        # The one in the docstring, which is also the shape every search that starts in the
        # middle of its range takes.
        assert list(waguess.oscillate(8, 2, 10)) == [8, 7, 9, 6, 10, 5, 4, 3, 2]

    def test_starting_at_the_top_walks_straight_down(self):
        # There is nothing above n_max to alternate with, so the two-sided phase ends
        # immediately and the rest is a plain descending range.
        assert list(waguess.oscillate(10, 2, 10)) == [10, 9, 8, 7, 6, 5, 4, 3, 2]

    @pytest.mark.parametrize("start", [8, 10])
    def test_the_whole_range_is_offered_once(self, start):
        offered = list(waguess.oscillate(start, 2, 10))
        assert sorted(offered) == list(range(2, 11))
        assert offered[0] == start


class TestOffsetValidation:
    """
    Both offsets are checked before anything is opened.

    An offset outside the header cannot be right, and the search would otherwise spend its
    whole budget proving it -- or read past the header and report nonsense.
    """

    LIMIT = C.HEADER_SIZE - 129

    @pytest.mark.parametrize("offset", [0, -1, C.HEADER_SIZE - 128, C.HEADER_SIZE])
    def test_a_data_offset_outside_the_header_is_refused(self, offset):
        with pytest.raises(WaCryptError, match=f"data offset must be between 1 and {self.LIMIT}"):
            waguess.guess(_args(data_offset=offset))

    @pytest.mark.parametrize("offset", [0, -1, C.HEADER_SIZE - 128, C.HEADER_SIZE])
    def test_an_iv_offset_outside_the_header_is_refused(self, offset):
        with pytest.raises(WaCryptError, match=f"IV offset must be between 1 and {self.LIMIT}"):
            waguess.guess(_args(iv_offset=offset))


class TestDecryptFailures:
    """
    What `decrypt` does when the write-out goes wrong.

    It runs after the search has already found offsets that work, so none of this is
    reachable from a successful run -- and every one of them has to come out as a
    DecryptionError, because that is what main() turns into an exit code and a message.
    """

    def test_no_cipher_at_all(self):
        with pytest.raises(DecryptionError, match="Could not create a decryption cipher"):
            waguess.decrypt(None, io.BytesIO(b""), io.BytesIO())

    def test_a_cipher_that_refuses(self):
        with pytest.raises(DecryptionError, match="Decryption failed"):
            waguess.decrypt(_Cipher(ValueError("MAC check failed")), io.BytesIO(b"data"), io.BytesIO())

    def test_running_out_of_memory_points_at_the_streaming_mode(self):
        with pytest.raises(DecryptionError, match="Out of RAM"):
            waguess.decrypt(_Cipher(MemoryError()), io.BytesIO(b"data"), io.BytesIO())

    def test_a_write_that_fails_is_an_io_error(self):
        with pytest.raises(DecryptionError, match="I/O error"):
            waguess.decrypt(_Cipher(zlib.compress(b"payload")), io.BytesIO(b"data"), _UnwritableFile())

    def test_a_truncated_stream_is_written_out_with_a_warning(self, caplog):
        # The offsets were right and the file is damaged: what decrypted is still worth
        # having, so it is written and the damage is reported rather than raised.
        out = _Sink()
        with caplog.at_level(logging.ERROR):
            waguess.decrypt(_Cipher(zlib.compress(b"payload")[:-4]), io.BytesIO(b"data"), out)
        assert b"payload" in out.written
        assert "truncated (damaged)" in caplog.text

    def test_a_zip_payload_is_written_undecompressed(self, caplog):
        with open("tests/res/test9.zip", "rb") as f:
            zipped = f.read()
        out = _Sink()
        with caplog.at_level(logging.INFO):
            waguess.decrypt(_Cipher(zipped), io.BytesIO(b"data"), out)
        assert out.written == zipped
        assert "ZIP file that I will not decompress" in caplog.text

    def test_data_that_is_neither_says_so(self, caplog):
        out = _Sink()
        with caplog.at_level(logging.ERROR):
            waguess.decrypt(_Cipher(b"\xff" * 64), io.BytesIO(b"data"), out)
        assert out.written == b"\xff" * 64
        assert "can't recognize decrypted data" in caplog.text


class _Cipher:
    """Stands in for the AES object: returns `answer`, or raises it if it is an exception."""

    def __init__(self, answer):
        self.answer = answer

    def decrypt(self, _data):
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class _Sink(io.BytesIO):
    """A BytesIO that keeps what it was given: decrypt() closes its output before returning."""

    written = b""

    def close(self):
        self.written = self.getvalue()
        super().close()


class _UnwritableFile(io.BytesIO):
    def write(self, _data):
        raise OSError("no space left on device")
