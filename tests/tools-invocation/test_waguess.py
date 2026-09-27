"""
waguess: decrypts a backup whose header the library cannot parse, by brute-forcing the IV
and data offsets and testing each candidate decryption.

150 statements with no test at all until now. lib/utils.py:test_decompression exists solely
to serve the search here.
"""

from __future__ import annotations

import pytest

from tests.utils.utils import Propen, cmp_files, rm_if_found

KEY15 = "tests/res/encrypted_backup.key"
KEY14 = "tests/res/key"
OUT = "waguess-test-out.db"

# The offsets waguess finds for each fixture, which are also what it tells the user to pass
# next time. They are properties of the format, not of the search, so they are pinned.
BACKUPS = [
    pytest.param(KEY15, "tests/res/msgstore.db.crypt15", 8, 131, id="crypt15"),
    pytest.param(KEY14, "tests/res/msgstore.db.crypt14", 67, 190, id="crypt14"),
    pytest.param(KEY14, "tests/res/msgstore.db.crypt12", 51, 67, id="crypt12"),
]


class TestWaGuess:
    def teardown_method(self):
        rm_if_found(OUT)

    @pytest.mark.parametrize("key, backup, iv_offset, data_offset", BACKUPS)
    def test_the_offsets_are_found_and_the_backup_decrypts(self, key, backup, iv_offset, data_offset):
        out, ret = Propen(f"waguess {key} {backup} {OUT}")
        assert ret == 0, out
        assert f"Offsets guessed (IV: {iv_offset}, data: {data_offset})" in out
        assert f"use -ivo {iv_offset} -do {data_offset}" in out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    @pytest.mark.parametrize("key, backup, iv_offset, data_offset", BACKUPS)
    def test_the_reported_offsets_work_when_given_back(self, key, backup, iv_offset, data_offset):
        # The advice the tool prints has to be advice that works.
        out, ret = Propen(f"waguess -ivo {iv_offset} -do {data_offset} {key} {backup} {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_offsets_that_are_wrong_are_still_searched_around(self):
        # -ivo/-do are a starting point, not a promise: a wrong pair must not stop the search.
        out, ret = Propen(f"waguess -ivo 9 -do 132 {KEY15} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_a_zip_payload_is_written_out_undecompressed(self):
        out, ret = Propen(f"waguess {KEY15} tests/res/stickers.backup.crypt15 {OUT}")
        assert ret == 0, out
        assert "ZIP file that I will not decompress automatically" in out
        with open(OUT, "rb") as f:
            written = f.read()
        with open("tests/res/test9.zip", "rb") as f:
            original = f.read()
        # waguess has no notion of the missing checksum a multi-file backup has, so it
        # writes the trailer out as data too; the archive itself is still intact at the front.
        assert written.startswith(original)


class TestCompressionLevels:
    """
    The search gates on the first two decrypted bytes matching a known zlib header before it
    spends time on a full test decryption. That list held only 78 01, the header for level 0
    and 1, which is what WhatsApp compressed with when this was written. It moved to level 9
    since -- a real 2.26 backup starts 78 da -- and every one of those was rejected outright,
    reported as "the key does not match this backup" on a key that matched perfectly.
    """

    ENCRYPTED = "waguess-level-test.crypt15"

    def teardown_method(self):
        rm_if_found(OUT)
        rm_if_found(self.ENCRYPTED)

    # 0/1 -> 78 01, 2-5 -> 78 5e, 6 -> 78 9c, 7-9 -> 78 da: every zlib header there is.
    @pytest.mark.parametrize("level", ["1", "3", "6", "9"])
    def test_a_backup_at_any_compression_level_is_found(self, level):
        out, ret = Propen(["waencrypt", "-c", level, KEY15, "tests/res/msgstore.db", self.ENCRYPTED])
        assert ret == 0, out
        out, ret = Propen(f"waguess {KEY15} {self.ENCRYPTED} {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_a_zip_payload_at_the_current_level_is_found(self):
        # What an incremental backup is: a ZIP, compressed at the level WhatsApp uses now.
        # It needs the header list and the ZIP-after-decompression check together.
        out, ret = Propen(["waencrypt", "-c", "9", KEY15, "tests/res/test9.zip", self.ENCRYPTED])
        assert ret == 0, out
        out, ret = Propen(f"waguess {KEY15} {self.ENCRYPTED} {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/test9.zip")


class TestRealCurrentBackups:
    """
    The two things that stopped waguess working on current backups, as they actually arrive:
    level 9 compression, and a payload that is a ZIP only after inflating. Both fixtures are
    real 2.26 headers -- see tests/lib/db/test_current_format.py for what was scrubbed.
    """

    def teardown_method(self):
        rm_if_found(OUT)

    def test_a_current_msgstore_is_found(self):
        out, ret = Propen(f"waguess {KEY15} tests/res/msgstore-2.26.db.crypt15 {OUT}")
        assert ret == 0, out

    def test_a_real_incremental_backup_is_found(self):
        # This one failed outright before: the header gate did not know 78 da, and the payload
        # check wanted SQLite where a compressed ZIP was.
        out, ret = Propen(f"waguess {KEY15} tests/res/msgstore-increment-2.26.crypt15 {OUT}")
        assert ret == 0, out
        with open(OUT, "rb") as f:
            assert f.read(4) == b"PK\x03\x04"


class TestWaGuessFailures:
    def teardown_method(self):
        rm_if_found(OUT)

    def test_the_wrong_key_is_reported_as_a_failed_search(self):
        out, ret = Propen(f"waguess {KEY14} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret != 0
        assert "Could not guess the offsets" in out

    def test_offsets_that_cannot_work_are_reported_as_a_failed_search(self):
        out, ret = Propen(f"waguess -ivo 1 -do 5 {KEY15} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret != 0
        assert "Could not guess the offsets" in out

    def test_a_file_too_small_to_be_a_backup_says_so(self):
        out, ret = Propen(f"waguess {KEY15} tests/res/test.json {OUT}")
        assert ret != 0
        assert "too small" in out

    def test_a_plaintext_database_is_recognised_as_one(self):
        # The commonest way to get the arguments the wrong way round: pointing the tool at
        # the decrypted database. The search would otherwise grind through every offset and
        # report a failure that says nothing about what actually happened.
        out, ret = Propen(f"waguess {KEY15} tests/res/msgstore.db {OUT}")
        assert ret != 0
        assert "The database file is not encrypted" in out
        assert "swap the input and the output files" in out

    def test_a_file_that_is_not_a_key_fails(self):
        out, ret = Propen("waguess tests/res/test.json tests/res/msgstore.db.crypt15 " + OUT)
        assert ret != 0
        assert "not a valid Java object" in out
