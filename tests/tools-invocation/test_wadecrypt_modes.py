"""
wadecrypt across the three formats and its two reading modes.

Everything else here only ever ran a crypt15 in RAM. The streaming mode (-nm / -bs) keeps a
two-chunk sliding window because the 36-byte trailer can straddle a buffer boundary, and it
has a separate copy of the crypt12 footer handling, the multifile handling and the ZIP
handling -- none of which the in-RAM path exercises.
"""

import zlib

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
    with open(backup, 'rb') as f:
        DatabaseFactory.from_file(f)
        return len(f.read())


@pytest.mark.parametrize("key, backup", BACKUPS)
class TestEveryFormatThroughTheCli:
    def test_in_ram(self, key, backup):
        try:
            out, ret = Propen("wadecrypt {} {} {}".format(key, backup, OUT))
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_streaming(self, key, backup):
        try:
            out, ret = Propen("wadecrypt -nm {} {} {}".format(key, backup, OUT))
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
            "last-chunk": n - 36,      # the final read returns exactly the 36-byte trailer
            "split": n - 20,           # the trailer straddles the last two chunks
            "exact-multiple": n,       # the final read returns nothing; the trailer is behind
        }[case]
        try:
            out, ret = Propen("wadecrypt -bs {} {} {} {}".format(buffer_size, key, backup, OUT))
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_a_small_buffer_walks_the_whole_file_in_many_chunks(self, key, backup):
        try:
            out, ret = Propen("wadecrypt -bs 1024 {} {} {}".format(key, backup, OUT))
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_a_buffer_too_small_to_hold_a_trailer_falls_back_to_the_default(self, key, backup):
        # Under 17 bytes the window logic cannot work, so the tool ignores the request
        # rather than producing nonsense.
        try:
            out, ret = Propen("wadecrypt -bs 8 {} {} {}".format(key, backup, OUT))
            assert ret == 0, out
            assert "Invalid buffer size" in out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_no_decompress_writes_the_raw_zlib_stream(self, key, backup):
        try:
            out, ret = Propen("wadecrypt -nd {} {} {}".format(key, backup, OUT))
            assert ret == 0, out
            with open(OUT, 'rb') as f:
                raw = f.read()
            assert raw[:2] == b'x\x01'
            with open("tests/res/msgstore.db", 'rb') as f:
                assert zlib.decompress(raw) == f.read()
        finally:
            rm_if_found(OUT)


class TestTruncatedBackups:
    """A backup that stops early fails both the tag check and the zlib stream."""

    def setup_method(self):
        with open("tests/res/msgstore.db.crypt15", 'rb') as f:
            data = f.read()
        with open(TRUNCATED, 'wb') as f:
            f.write(data[:-200])

    def teardown_method(self):
        rm_if_found(TRUNCATED)
        rm_if_found(OUT)

    def test_streaming_reports_the_damaged_stream_as_well_as_the_tag(self):
        out, ret = Propen("wadecrypt -nm {} {} {}".format(KEY15, TRUNCATED, OUT))
        assert ret != 0
        assert "Authentication tag mismatch" in out
        assert "truncated (damaged)" in out

    def test_force_writes_the_partial_output_anyway(self):
        out, ret = Propen("wadecrypt -nm -f {} {} {}".format(KEY15, TRUNCATED, OUT))
        assert ret == 0, out
        from os.path import exists, getsize
        assert exists(OUT) and getsize(OUT) > 0


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
        out, ret = Propen("wadecrypt {}{} tests/res/stickers.backup.crypt15 {}"
                          .format(mode, KEY15, self.OUT_ZIP))
        assert ret == 0, out
        assert "ZIP file that I will not decompress automatically" in out
        assert cmp_files(self.OUT_ZIP, "tests/res/test9.zip")

    def test_the_wrong_key_is_reported_as_unrecognisable_rather_than_as_a_zip(self):
        # Same zlib.error, different cause: the ZIP message must not be the catch-all.
        out, ret = Propen("wadecrypt -f {} tests/res/stickers.backup.crypt15 {}"
                          .format(KEY14, self.OUT_ZIP))
        assert "I can't recognize decrypted data" in out
        assert "ZIP file" not in out
