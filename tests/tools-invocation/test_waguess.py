"""
waguess: decrypts a backup whose header the library cannot parse, by brute-forcing the IV
and data offsets and testing each candidate decryption.

150 statements with no test at all until now. lib/utils.py:test_decompression exists solely
to serve the search here.
"""

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
        out, ret = Propen("waguess {} {} {}".format(key, backup, OUT))
        assert ret == 0, out
        assert "Offsets guessed (IV: {}, data: {})".format(iv_offset, data_offset) in out
        assert "use -ivo {} -do {}".format(iv_offset, data_offset) in out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    @pytest.mark.parametrize("key, backup, iv_offset, data_offset", BACKUPS)
    def test_the_reported_offsets_work_when_given_back(self, key, backup, iv_offset, data_offset):
        # The advice the tool prints has to be advice that works.
        out, ret = Propen("waguess -ivo {} -do {} {} {} {}"
                          .format(iv_offset, data_offset, key, backup, OUT))
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_offsets_that_are_wrong_are_still_searched_around(self):
        # -ivo/-do are a starting point, not a promise: a wrong pair must not stop the search.
        out, ret = Propen("waguess -ivo 9 -do 132 {} tests/res/msgstore.db.crypt15 {}"
                          .format(KEY15, OUT))
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_a_zip_payload_is_written_out_undecompressed(self):
        out, ret = Propen("waguess {} tests/res/stickers.backup.crypt15 {}".format(KEY15, OUT))
        assert ret == 0, out
        assert "ZIP file that I will not decompress automatically" in out
        with open(OUT, 'rb') as f:
            written = f.read()
        with open("tests/res/test9.zip", 'rb') as f:
            original = f.read()
        # waguess has no notion of the missing checksum a multi-file backup has, so it
        # writes the trailer out as data too; the archive itself is still intact at the front.
        assert written.startswith(original)


class TestWaGuessFailures:
    def teardown_method(self):
        rm_if_found(OUT)

    def test_the_wrong_key_is_reported_as_a_failed_search(self):
        out, ret = Propen("waguess {} tests/res/msgstore.db.crypt15 {}".format(KEY14, OUT))
        assert ret != 0
        assert "Could not guess the offsets" in out

    def test_offsets_that_cannot_work_are_reported_as_a_failed_search(self):
        out, ret = Propen("waguess -ivo 1 -do 5 {} tests/res/msgstore.db.crypt15 {}"
                          .format(KEY15, OUT))
        assert ret != 0
        assert "Could not guess the offsets" in out

    def test_a_file_too_small_to_be_a_backup_says_so(self):
        out, ret = Propen("waguess {} tests/res/test.json {}".format(KEY15, OUT))
        assert ret != 0
        assert "too small" in out

    def test_a_file_that_is_not_a_key_fails(self):
        out, ret = Propen("waguess tests/res/test.json tests/res/msgstore.db.crypt15 " + OUT)
        assert ret != 0
        assert "not a valid Java object" in out
