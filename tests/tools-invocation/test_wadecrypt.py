"""
wadecrypt's exit codes and its --force flag.

--force went dead in the move to the logging framework: it was still documented but did
nothing, because every check it used to gate had become a log call that stops nothing. These
tests pin down both halves of it -- a failed check aborts, and --force writes the output
anyway.
"""

from os.path import exists

from tests.utils.utils import Propen, cmp_files, rm_if_found

CORRUPT = "corrupted.db.crypt15"
OUT = "wadecrypt-test-out.db"


def make_corrupted_backup():
    """A real crypt15 backup with one bit flipped in the ciphertext."""
    with open("tests/res/msgstore.db.crypt15", 'rb') as f:
        data = bytearray(f.read())
    # Well before the authentication tag and the checksum, so the tag check is what fails.
    data[-40] ^= 0xFF
    with open(CORRUPT, 'wb') as f:
        f.write(bytes(data))


class TestWaDecrypt:
    def test_decrypts_a_good_backup(self):
        try:
            out, ret = Propen("wadecrypt tests/res/encrypted_backup.key "
                              "tests/res/msgstore.db.crypt15 " + OUT)
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(OUT)

    def test_corrupted_backup_fails_without_force(self):
        try:
            make_corrupted_backup()
            out, ret = Propen("wadecrypt tests/res/encrypted_backup.key " + CORRUPT + " " + OUT)
            assert ret != 0
            assert "Authentication tag mismatch" in out
            assert "--force" in out
        finally:
            rm_if_found(CORRUPT)
            rm_if_found(OUT)

    def test_corrupted_backup_is_written_with_force(self):
        try:
            make_corrupted_backup()
            out, ret = Propen("wadecrypt -f tests/res/encrypted_backup.key " + CORRUPT + " " + OUT)
            assert ret == 0, out
            assert "Authentication tag mismatch" in out
            assert exists(OUT)
            # It is written, but it is not the real database -- that is what the tag was
            # telling us, and why writing it takes an explicit flag.
            assert not cmp_files(OUT, "tests/res/msgstore.db")
        finally:
            rm_if_found(CORRUPT)
            rm_if_found(OUT)

    def test_corrupted_backup_fails_without_force_when_streaming(self):
        """The --no-mem path decrypts in chunks and checks the tag separately."""
        try:
            make_corrupted_backup()
            out, ret = Propen("wadecrypt -nm tests/res/encrypted_backup.key " + CORRUPT + " " + OUT)
            assert ret != 0
            assert "Authentication tag mismatch" in out
        finally:
            rm_if_found(CORRUPT)
            rm_if_found(OUT)

    def test_streaming_succeeds_with_force(self):
        try:
            make_corrupted_backup()
            out, ret = Propen("wadecrypt -nm -f tests/res/encrypted_backup.key "
                              + CORRUPT + " " + OUT)
            assert ret == 0, out
            assert exists(OUT)
        finally:
            rm_if_found(CORRUPT)
            rm_if_found(OUT)

    def test_unusable_key_file_fails(self):
        """Used to carry on with a None key and die with an AttributeError."""
        try:
            out, ret = Propen("wadecrypt tests/res/test.json "
                              "tests/res/msgstore.db.crypt15 " + OUT)
            assert ret != 0
            assert "Traceback" not in out
        finally:
            rm_if_found(OUT)

    def test_non_hex_key_of_the_right_length_fails(self):
        """Used to die with "object of type 'NoneType' has no len()"."""
        try:
            out, ret = Propen("wadecrypt " + "z" * 64 + " "
                              "tests/res/msgstore.db.crypt15 " + OUT)
            assert ret != 0
            assert "Traceback" not in out
            assert "TypeError" not in out
        finally:
            rm_if_found(OUT)

    def test_a_file_that_is_not_a_backup_fails(self):
        try:
            out, ret = Propen("wadecrypt tests/res/encrypted_backup.key "
                              "tests/res/test.json " + OUT)
            assert ret != 0
            assert "Traceback" not in out
        finally:
            rm_if_found(OUT)
