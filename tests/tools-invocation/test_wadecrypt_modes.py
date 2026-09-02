"""
wadecrypt across the three formats and its two reading modes.

Everything else here only ever ran a crypt15 in RAM. The streaming mode (-nm / -bs) keeps a
two-chunk sliding window because the 36-byte trailer can straddle a buffer boundary, and it
has a separate copy of the crypt12 footer handling, the multifile handling and the ZIP
handling -- none of which the in-RAM path exercises.
"""

from __future__ import annotations

import zlib
from os.path import exists, getsize

import pytest

from tests.utils.utils import Propen, cmp_files, rm_if_found

KEY15 = "tests/res/encrypted_backup.key"
KEY14 = "tests/res/key"
OUT = "wadecrypt-modes-out.db"
TRUNCATED = "truncated.db.crypt15"

BACKUPS = [
    pytest.param(KEY15, "tests/res/msgstore.db.crypt15", id="crypt15"),
    pytest.param(KEY14, "tests/res/msgstore.db.crypt14", id="crypt14"),
    pytest.param(KEY14, "tests/res/msgstore.db.crypt12", id="crypt12"),
]


def ciphertext_length(backup: str) -> int:
    """How many bytes follow the header -- what the chunk loop actually walks over."""
    from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory

    with open(backup, "rb") as f:
        DatabaseFactory.from_file(f)
        return len(f.read())


@pytest.mark.parametrize("key, backup", BACKUPS)
class TestEveryFormatThroughTheCli:
    def test_in_ram(self, key, backup):
        try:
            out, ret = Propen(f"wadecrypt {key} {backup} {OUT}")
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_streaming(self, key, backup):
        try:
            out, ret = Propen(f"wadecrypt -nm {key} {backup} {OUT}")
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    @pytest.mark.parametrize("case", ["last-chunk", "split", "exact-multiple"])
    def test_the_trailer_lands_on_every_side_of_a_buffer_boundary(self, key, backup, case):
        # The trailer is 36 bytes and the loop handles three cases; which one runs depends
        # entirely on where the last read falls, so the buffer size is chosen to force each.
        n = ciphertext_length(backup)
        buffer_size = {
            "last-chunk": n - 36,  # the final read returns exactly the 36-byte trailer
            "split": n - 20,  # the trailer straddles the last two chunks
            "exact-multiple": n,  # the final read returns nothing; the trailer is behind
        }[case]
        try:
            out, ret = Propen(f"wadecrypt -bs {buffer_size} {key} {backup} {OUT}")
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_a_small_buffer_walks_the_whole_file_in_many_chunks(self, key, backup):
        try:
            out, ret = Propen(f"wadecrypt -bs 1024 {key} {backup} {OUT}")
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_a_buffer_too_small_to_hold_a_trailer_falls_back_to_the_default(self, key, backup):
        # Under 17 bytes the window logic cannot work, so the tool ignores the request
        # rather than producing nonsense.
        try:
            out, ret = Propen(f"wadecrypt -bs 8 {key} {backup} {OUT}")
            assert ret == 0, out
            assert "Invalid buffer size" in out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    @pytest.mark.parametrize("mode", ["", "-nm "], ids=["in-ram", "streaming"])
    def test_no_decompress_writes_the_raw_zlib_stream(self, key, backup, mode):
        # Both modes, because each has its own copy of the decompress-or-not handling: the
        # streaming one has to keep the choice across every chunk and across the trailer.
        try:
            out, ret = Propen(f"wadecrypt {mode}-nd {key} {backup} {OUT}")
            assert ret == 0, out
            with open(OUT, "rb") as f:
                raw = f.read()
            assert raw[:2] == b"x\x01"
            with open("tests/res/msgstore.db", "rb") as f:
                assert zlib.decompress(raw) == f.read()
        finally:
            rm_if_found(OUT)


class TestTruncatedBackups:
    """A backup that stops early fails both the tag check and the zlib stream."""

    def setup_method(self):
        with open("tests/res/msgstore.db.crypt15", "rb") as f:
            data = f.read()
        with open(TRUNCATED, "wb") as f:
            f.write(data[:-200])

    def teardown_method(self):
        rm_if_found(TRUNCATED)
        rm_if_found(OUT)

    def test_streaming_reports_the_damaged_stream_as_well_as_the_tag(self):
        out, ret = Propen(f"wadecrypt -nm {KEY15} {TRUNCATED} {OUT}")
        assert ret != 0
        assert "Authentication tag mismatch" in out
        assert "truncated (damaged)" in out

    def test_force_writes_the_partial_output_anyway(self):
        out, ret = Propen(f"wadecrypt -nm -f {KEY15} {TRUNCATED} {OUT}")
        assert ret == 0, out
        assert exists(OUT) and getsize(OUT) > 0


class TestBufferSizes:
    """-bs is checked before the output file is touched, since it decides the whole read loop."""

    def teardown_method(self):
        rm_if_found(OUT)

    @pytest.mark.parametrize("size", ["0", "1", "-1"])
    def test_a_buffer_size_that_cannot_work_is_refused(self, size):
        out, ret = Propen(["wadecrypt", "-bs", size, KEY15, "tests/res/msgstore.db.crypt15", OUT])
        assert ret != 0
        assert "Invalid buffer size" in out
        assert not exists(OUT)

    def test_the_wrong_key_is_reported_chunk_by_chunk_and_still_written_under_force(self):
        # The streaming path has its own copy of the "is this even zlib" handling, one that
        # has to keep writing after it has given up on decompressing: the first chunk decides
        # and every later one follows it.
        out, ret = Propen(["wadecrypt", "-bs", "4096", "-f", KEY14, "tests/res/msgstore.db.crypt15", OUT])
        assert ret == 0, out
        assert "I can't recognize decrypted data" in out
        assert exists(OUT) and getsize(OUT) > 4096


class TestAFileWithNoCiphertext:
    """A backup whose header is all there is: nothing to decrypt, and it has to say so."""

    HEADER_ONLY = "wadecrypt-header-only.crypt15"

    def setup_method(self):
        # The factory leaves the stream on the first ciphertext byte, which is exactly where
        # this file has to stop.
        from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory

        with open("tests/res/msgstore.db.crypt15", "rb") as f:
            DatabaseFactory.from_file(f)
            header_length = f.tell()
            f.seek(0)
            header = f.read(header_length)
        with open(self.HEADER_ONLY, "wb") as f:
            f.write(header)

    def teardown_method(self):
        rm_if_found(self.HEADER_ONLY)
        rm_if_found(OUT)

    def test_streaming_says_the_file_is_empty_or_truncated(self):
        out, ret = Propen(f"wadecrypt -nm {KEY15} {self.HEADER_ONLY} {OUT}")
        assert ret != 0
        assert "empty or truncated" in out


class TestMultiFileBackups:
    """
    tests/res/stickers.backup.crypt15 is what a stickers or wallpapers backup looks like:
    the plaintext is a ZIP rather than a zlib'd SQLite database, and there is no trailing
    md5 of the file, so the tag sits where the checksum would be.
    """

    OUT_ZIP = "wadecrypt-modes-out.zip"

    def teardown_method(self):
        rm_if_found(self.OUT_ZIP)

    @pytest.mark.parametrize("mode", ["", "-nm "], ids=["in-ram", "streaming"])
    def test_a_zip_payload_is_written_out_undecompressed(self, mode):
        out, ret = Propen(f"wadecrypt {mode}{KEY15} tests/res/stickers.backup.crypt15 {self.OUT_ZIP}")
        assert ret == 0, out
        assert "ZIP file that I will not decompress automatically" in out
        assert cmp_files(self.OUT_ZIP, "tests/res/test9.zip")

    def test_the_wrong_key_is_reported_as_unrecognisable_rather_than_as_a_zip(self):
        # Same zlib.error, different cause: the ZIP message must not be the catch-all.
        out, _ret = Propen(f"wadecrypt -f {KEY14} tests/res/stickers.backup.crypt15 {self.OUT_ZIP}")
        assert "I can't recognize decrypted data" in out
        assert "ZIP file" not in out
