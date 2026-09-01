"""
The GUI's decisions, none of which need a display.

Everything the window does that could be wrong lives in gui/core.py so that it can be tested
here: what a chosen file actually is, what to call the output, which of the user's mistakes to
name before doing any work, and which sentence a failure deserves. gui/app.py is left holding
only widget wiring, which test_app.py smoke-tests.
"""

import logging
import queue

import pytest

from tests.utils.utils import cmp_files
from wa_crypt_tools.gui import core
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import (
    DecryptionError,
    HeaderError,
    IntegrityError,
    InvalidKeyError,
    WaCryptError,
)
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

KEY15 = "tests/res/encrypted_backup.key"
KEY14 = "tests/res/key"
PLAIN = "tests/res/msgstore.db"


def hex_key() -> str:
    """The 64-character root key the GUI accepts in place of a key file."""
    return KeyFactory.new(KEY15).get_root().hex()


class TestDescribeBackup:
    def test_crypt15(self):
        d = core.describe_backup("tests/res/msgstore.db.crypt15")
        assert d.format == "Crypt15"
        assert "IV:" in d.detail
        assert "WhatsApp version" in d.detail
        assert d.warning is None
        # The headline is the part a non-technical user reads, so it must carry
        # neither an IV nor a feature number.
        assert d.headline == "Crypt15 backup — WhatsApp 2.22.5.13, phone number ending 67"

    def test_crypt14(self):
        d = core.describe_backup("tests/res/msgstore.db.crypt14")
        assert d.format == "Crypt14"
        # Only a crypt14 header carries these, and only header_info renders them.
        assert "Key version" in d.detail
        assert "Server salt" in d.detail
        assert d.headline.startswith("Crypt14 backup — WhatsApp ")

    def test_crypt12(self):
        # Crypt12 has no protobuf prefix at all, so the summary comes from Database12.__str__.
        d = core.describe_backup("tests/res/msgstore.db.crypt12")
        assert d.format == "Crypt12"
        assert "cipher_version" in d.detail
        # Nothing in a crypt12 header names the app version or the phone number.
        assert d.headline == "Crypt12 backup"

    def test_a_real_226_msgstore_lists_its_features(self):
        d = core.describe_backup("tests/res/msgstore-2.26.db.crypt15")
        assert d.format == "Crypt15"
        assert "Features:" in d.detail

    def test_a_backup_that_is_not_a_msgstore_has_no_features(self):
        # wa.db carries no migration flags, which is the thing wainfo calls "no feature table".
        d = core.describe_backup("tests/res/wa-2.26.db.crypt15")
        assert d.format == "Crypt15"
        assert "Features:" not in d.detail

    def test_multi_file_backup(self):
        d = core.describe_backup("tests/res/stickers.backup.crypt15")
        assert d.format == "Crypt15"

    def test_a_plain_database_is_not_a_backup(self):
        # The commonest mistake: pointing the backup field at an already-decrypted file.
        with pytest.raises(WaCryptError):
            core.describe_backup(PLAIN)

    def test_a_missing_file_raises_oserror(self):
        with pytest.raises(OSError):
            core.describe_backup("tests/res/there-is-no-such-file")

    def test_a_suspect_header_still_describes_what_it_read(self, monkeypatch):
        # The factory raises IntegrityError for a header it could parse but does not trust
        # (a 15-byte IV, say), attaching the database it built. wainfo prints that anyway
        # rather than showing nothing, and the info pane should do the same -- with a
        # warning, so the user is not told a broken backup is fine.
        with open("tests/res/msgstore.db.crypt15", 'rb') as f:
            salvaged = DatabaseFactory.from_file(f)

        def suspect(_stream):
            raise IntegrityError("IV is not 16 bytes long", data=salvaged)

        monkeypatch.setattr(DatabaseFactory, "from_file", staticmethod(suspect))
        d = core.describe_backup("tests/res/msgstore.db.crypt15")
        assert d.format == "Crypt15"
        assert "IV:" in d.detail
        assert "IV is not 16 bytes long" in d.warning

    def test_an_unsalvageable_header_raises(self, monkeypatch):
        def hopeless(_stream):
            raise IntegrityError("nothing could be read", data=None)

        monkeypatch.setattr(DatabaseFactory, "from_file", staticmethod(hopeless))
        with pytest.raises(IntegrityError):
            core.describe_backup("tests/res/msgstore.db.crypt15")


class TestSuggestOutput:
    @pytest.mark.parametrize("given,expected", [
        ("msgstore.db.crypt15", "msgstore.db"),
        ("msgstore.db.crypt14", "msgstore.db"),
        ("msgstore.db.crypt12", "msgstore.db"),
        ("stickers.backup.crypt15", "stickers.backup"),
        # The suffix is what WhatsApp writes, but a user's filesystem may have shouted it.
        ("BACKUP.CRYPT15", "BACKUP"),
        # Anything else keeps its name and gains a suffix, rather than losing information.
        ("avatar-password.bkup", "avatar-password.bkup.decrypted"),
    ])
    def test_suffix_handling(self, given, expected):
        assert core.suggest_output(given) == expected

    def test_keeps_the_directory(self):
        assert core.suggest_output("/tmp/some dir/msgstore.db.crypt15") == "/tmp/some dir/msgstore.db"

    def test_nothing_chosen_yet(self):
        assert core.suggest_output("") == ""


class TestProblems:
    def good(self, tmp_path, **over):
        kwargs = {"key": KEY15, "key_is_file": True,
                  "encrypted": "tests/res/msgstore.db.crypt15",
                  "output": str(tmp_path / "out.db"), "overwrite": False}
        kwargs.update(over)
        return core.problems(**kwargs)

    def test_a_valid_form_has_no_problems(self, tmp_path):
        assert self.good(tmp_path) == []

    def test_a_valid_hex_key_has_no_problems(self, tmp_path):
        assert self.good(tmp_path, key=hex_key(), key_is_file=False) == []

    def test_hex_key_may_be_spaced_out(self, tmp_path):
        # A key read off a screenshot is often transcribed in groups.
        spaced = " ".join(hex_key()[i:i + 8] for i in range(0, 64, 8))
        assert self.good(tmp_path, key=spaced, key_is_file=False) == []

    def test_no_key_file(self, tmp_path):
        assert "key file" in self.good(tmp_path, key="  ")[0]

    def test_no_hex_key(self, tmp_path):
        assert "64-character" in self.good(tmp_path, key="", key_is_file=False)[0]

    def test_missing_key_file(self, tmp_path):
        assert "does not exist" in self.good(tmp_path, key="tests/res/nope.key")[0]

    def test_short_hex_key(self, tmp_path):
        problems = self.good(tmp_path, key=hex_key()[:63], key_is_file=False)
        assert "64 characters" in problems[0] and "63" in problems[0]

    def test_hex_key_that_is_not_hex(self, tmp_path):
        problems = self.good(tmp_path, key="z" * 64, key_is_file=False)
        assert "0-9" in problems[0]

    def test_no_backup_chosen(self, tmp_path):
        assert "backup" in self.good(tmp_path, encrypted="")[0]

    def test_missing_backup(self, tmp_path):
        assert "does not exist" in self.good(tmp_path, encrypted="tests/res/nope.crypt15")[0]

    def test_no_output_chosen(self, tmp_path):
        assert "save" in self.good(tmp_path, output="")[0].lower()

    def test_existing_output_needs_overwrite(self, tmp_path):
        out = tmp_path / "out.db"
        out.write_bytes(b"something the user cares about")
        assert "Overwrite" in self.good(tmp_path, output=str(out))[0]

    def test_existing_output_is_fine_once_ticked(self, tmp_path):
        out = tmp_path / "out.db"
        out.write_bytes(b"something the user stopped caring about")
        assert self.good(tmp_path, output=str(out), overwrite=True) == []

    def test_refuses_to_write_over_the_backup_itself(self, tmp_path):
        # Ticking Overwrite must not turn the source into the destination.
        problems = self.good(tmp_path, output="tests/res/msgstore.db.crypt15", overwrite=True)
        assert len(problems) == 1
        assert "backup you are decrypting" in problems[0]

    def test_reports_every_problem_at_once(self, tmp_path):
        # One trip to the user, not one per mistake.
        assert len(self.good(tmp_path, key="", encrypted="", output="")) == 3


class TestFriendly:
    @pytest.mark.parametrize("error,expected", [
        (InvalidKeyError("x"), "key file"),
        (HeaderError("x"), "right way round"),
        (DecryptionError("x"), "does not match"),
        (IntegrityError("x"), "damaged"),
        (WaCryptError("plain message"), "plain message"),
    ])
    def test_each_error_gets_its_own_sentence(self, error, expected):
        assert expected in core.friendly(error)

    def test_a_missing_file_names_the_file(self):
        try:
            open("tests/res/there-is-no-such-file", 'rb')
        except OSError as e:
            assert "there-is-no-such-file" in core.friendly(e)

    def test_anything_else_still_says_something(self):
        assert "boom" in core.friendly(RuntimeError("boom"))

    def test_no_sentence_is_a_bare_class_name(self):
        # A dialog reading "IntegrityError" helps nobody.
        for error in (InvalidKeyError("x"), HeaderError("x"), DecryptionError("x"),
                      IntegrityError("x")):
            assert type(error).__name__ not in core.friendly(error)


class TestLogCapture:
    def test_records_reach_the_queue(self):
        q = queue.Queue()
        with core.captured_logs(q):
            logging.getLogger("wa_crypt_tools.lib.whatever").warning("hello")
        levelno, text = q.get_nowait()
        assert levelno == logging.WARNING
        assert "hello" in text

    def test_debug_is_quiet_unless_verbose(self):
        q = queue.Queue()
        with core.captured_logs(q):
            logging.getLogger("wa_crypt_tools.lib.whatever").debug("noise")
        assert q.empty()

    def test_verbose_lets_debug_through(self):
        q = queue.Queue()
        with core.captured_logs(q, verbose=True):
            logging.getLogger("wa_crypt_tools.lib.whatever").debug("noise")
        assert "noise" in q.get_nowait()[1]

    def test_the_handler_is_removed_afterwards(self):
        logger = logging.getLogger("wa_crypt_tools")
        before = list(logger.handlers)
        q = queue.Queue()
        with core.captured_logs(q):
            pass
        assert logger.handlers == before

    def test_the_handler_is_removed_even_when_the_work_raises(self):
        logger = logging.getLogger("wa_crypt_tools")
        before = list(logger.handlers)
        with pytest.raises(RuntimeError), core.captured_logs(queue.Queue()):
            raise RuntimeError("boom")
        assert logger.handlers == before


class TestRunDecrypt:
    def test_crypt15_with_a_key_file(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15", output=str(out))
        assert cmp_files(str(out), PLAIN)

    def test_crypt15_with_a_hex_key(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=hex_key(), encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out))
        assert cmp_files(str(out), PLAIN)

    def test_crypt14(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=KEY14, encrypted="tests/res/msgstore.db.crypt14", output=str(out))
        assert cmp_files(str(out), PLAIN)

    def test_crypt12(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=KEY14, encrypted="tests/res/msgstore.db.crypt12", output=str(out))
        assert cmp_files(str(out), PLAIN)

    def test_low_memory_takes_the_chunked_path(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out), low_memory=True)
        assert cmp_files(str(out), PLAIN)

    def test_no_decompress_leaves_the_zlib_stream(self, tmp_path):
        out = tmp_path / "msgstore.zlib"
        core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out), no_decompress=True)
        assert out.read_bytes()[:2] == bytes.fromhex("7801")

    def test_try_harder_finds_the_offsets(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out), try_harder=True)
        assert cmp_files(str(out), PLAIN)

    def test_the_wrong_key_is_an_error(self, tmp_path):
        out = tmp_path / "msgstore.db"
        with pytest.raises(WaCryptError):
            core.run_decrypt(key="00" * 32, encrypted="tests/res/msgstore.db.crypt15",
                             output=str(out))

    def test_force_writes_the_output_anyway(self, tmp_path):
        out = tmp_path / "msgstore.db"
        core.run_decrypt(key="00" * 32, encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out), force=True)
        assert out.exists()

    def test_an_existing_output_is_refused(self, tmp_path):
        out = tmp_path / "msgstore.db"
        out.write_bytes(b"precious")
        with pytest.raises(WaCryptError):
            core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15",
                             output=str(out))
        assert out.read_bytes() == b"precious"

    def test_overwrite_allows_it(self, tmp_path):
        out = tmp_path / "msgstore.db"
        out.write_bytes(b"precious")
        core.run_decrypt(key=KEY15, encrypted="tests/res/msgstore.db.crypt15",
                         output=str(out), overwrite=True)
        assert cmp_files(str(out), PLAIN)

    def test_a_failed_try_harder_leaves_no_output_behind(self, tmp_path):
        # waguess opens its output for writing before it knows whether it can decrypt, so
        # core has to stage it: a failure must not leave the user an empty file that looks
        # like a result.
        out = tmp_path / "msgstore.db"
        with pytest.raises(WaCryptError):
            core.run_decrypt(key="00" * 32, encrypted="tests/res/msgstore.db.crypt15",
                             output=str(out), try_harder=True)
        assert not out.exists()
        assert list(tmp_path.iterdir()) == []
