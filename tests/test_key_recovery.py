"""
`key_works`: the oracle that lets a misread key be repaired.

Guessing at a key is only safe because every guess is checked against the backup before it is
used, so nothing here is ever a guess that got through -- a candidate either decrypted the
start of the file into something a backup can actually start with, or it did not. These tests
pin down that check on its own, away from OCR, because it is what the whole recovery rests on.

The trick is waguess's, applied to keys instead of offsets: decrypt the first two bytes and
compare them against the headers a compressed or zipped payload has to begin with.
"""

from __future__ import annotations

import pytest

from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.wadecrypt import PROBE_BYTES, corrected, key_works

#: The root key of tests/res/encrypted_backup.key, which every crypt15 fixture is under.
ROOT = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"


def probe_of(backup):
    """The IV and the first bytes of ciphertext, the way wadecrypt hands them over."""
    with open(backup, "rb") as f:
        db = DatabaseFactory.from_file(f)
        return db.get_iv(), f.read(PROBE_BYTES)


class TestKeyWorks:
    def test_the_right_key_is_recognised(self):
        iv, probe = probe_of("tests/res/msgstore.db.crypt15")
        assert key_works(bytes.fromhex(ROOT), iv, probe)

    def test_a_key_one_digit_out_is_rejected(self):
        # The case the whole feature exists for. It has to be rejected here, or the search
        # would stop on the first thing it tried and report a wrong key as correct.
        iv, probe = probe_of("tests/res/msgstore.db.crypt15")
        assert not key_works(bytes.fromhex(ROOT[:-1] + "0"), iv, probe)

    @pytest.mark.parametrize("key", ["00" * 32, "ff" * 32, "ab" * 32])
    def test_unrelated_keys_are_rejected(self, key):
        iv, probe = probe_of("tests/res/msgstore.db.crypt15")
        assert not key_works(bytes.fromhex(key), iv, probe)

    def test_a_zip_payload_is_recognised_too(self):
        # stickers.backup.crypt15 is a multi-file backup written with --no-compress, so its
        # plaintext starts "PK" rather than a zlib header. Both are in C.ZLIB_HEADERS, and
        # both have to be, or the recovery would silently not work for multi-file backups.
        iv, probe = probe_of("tests/res/stickers.backup.crypt15")
        assert key_works(bytes.fromhex(ROOT), iv, probe)

    def test_a_short_probe_does_not_raise(self):
        iv, _ = probe_of("tests/res/msgstore.db.crypt15")
        assert not key_works(bytes.fromhex(ROOT), iv, b"")

    def test_a_wrong_length_key_is_rejected_rather_than_raising(self):
        # Every failure here has to be a False. The search runs tens of thousands of these,
        # and an exception escaping one of them would abort a decryption that was about to
        # succeed on the next candidate.
        iv, probe = probe_of("tests/res/msgstore.db.crypt15")
        assert not key_works(b"\x00" * 16, iv, probe)


class TestProbingTheBackup:
    """
    `corrected` reads a little ciphertext to check the key against, and puts the stream back.

    It runs on a stream the caller is about to decrypt from, so getting that wrong would
    break a decryption that was going to work. When the stream cannot be rewound it does
    nothing at all, which is what it did before any of this existed.
    """

    def test_a_stream_that_cannot_be_rewound_leaves_the_key_alone(self):
        key = KeyFactory.from_file("tests/res/encrypted_backup.key")
        with open("tests/res/msgstore.db.crypt15", "rb") as f:
            db = DatabaseFactory.from_file(f)
            # The key is given as 64 digits rather than as the file, so that this is a key
            # the repair would otherwise have something to say about.
            assert corrected(key, ROOT, Unrewindable(f), db.get_iv()) is key

    def test_a_key_file_is_never_second_guessed(self):
        # Its digits came out of WhatsApp's own file byte for byte; there is no misreading
        # to repair, so the backup is not even probed.
        key = KeyFactory.from_file("tests/res/encrypted_backup.key")
        assert corrected(key, "tests/res/encrypted_backup.key", None, b"\x00" * 16) is key


class Unrewindable:
    """A stream that reads but cannot say where it is -- a pipe, in other words."""

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def tell(self):
        raise OSError("underlying stream is not seekable")

    def read(self, size=-1):
        return self._wrapped.read(size)


class TestTheKeyItIsCheckedAgainst:
    def test_the_fixture_key_really_is_this_root(self):
        # Everything above is only meaningful while this holds.
        assert KeyFactory.from_file("tests/res/encrypted_backup.key").get_root().hex() == ROOT
