"""
waencrypt, which had no invocation test at all despite being the tool marked beta.

Everything is checked by round-tripping through wadecrypt rather than by comparing bytes:
zlib-ng (CPython 3.14+ on Windows) compresses differently, so only the plaintext is stable
across platforms. The one byte-for-byte check is guarded on that.
"""

import zlib

import pytest

from tests.utils.utils import Propen, cmp_files, rm_if_found

KEY15 = "tests/res/encrypted_backup.key"
KEY14 = "tests/res/key"
PLAIN = "tests/res/msgstore.db"
OUT = "waencrypt-test-out.crypt"
ROUNDTRIP = "waencrypt-test-roundtrip.db"

CLASSIC_ZLIB = ("zlib-ng" not in zlib.ZLIB_VERSION
                and "zlib-ng" not in zlib.ZLIB_RUNTIME_VERSION)


def cleanup():
    rm_if_found(OUT)
    rm_if_found(ROUNDTRIP)


def roundtrip(key: str, *extra: str) -> str:
    """Encrypts the reference database, decrypts it back, and returns wadecrypt's output."""
    out, ret = Propen(["waencrypt", *extra, key, PLAIN, OUT])
    assert ret == 0, out
    out, ret = Propen("wadecrypt {} {} {}".format(key, OUT, ROUNDTRIP))
    assert ret == 0, out
    return out


class TestRoundTrips:
    def teardown_method(self):
        cleanup()

    @pytest.mark.parametrize("key, type_", [
        pytest.param(KEY15, "15", id="crypt15"),
        pytest.param(KEY14, "14", id="crypt14"),
        pytest.param(KEY14, "12", id="crypt12"),
    ])
    def test_every_type_survives_a_round_trip(self, key, type_):
        roundtrip(key, "--type", type_, "--jid", "67")
        assert cmp_files(ROUNDTRIP, PLAIN)

    def test_a_fixed_iv_is_used_verbatim(self):
        iv = "c395ee009cf8b68ac0ea760550f6559c"
        roundtrip(KEY15, "--iv", iv)
        out, ret = Propen("wainfo " + OUT)
        assert ret == 0, out
        assert "IV: " + iv in out

    def test_no_compress_writes_the_input_unchanged(self):
        roundtrip(KEY15, "--no-compress")
        # wadecrypt cannot decompress it either, so what comes back is the input verbatim.
        assert cmp_files(ROUNDTRIP, PLAIN)

    def test_features_and_version_end_up_in_the_header(self):
        # --enable-features takes nargs='*', so it has to come before the other options:
        # placed just before the positionals it swallows the keyfile as a feature number.
        out, ret = Propen(["waencrypt", "--enable-features", "5", "7", "13",
                           "--type", "15", "--jid", "42", "--wa-version", "2.24.1.1",
                           "--max-feature", "37", KEY15, PLAIN, OUT])
        assert ret == 0, out
        out, ret = Propen("wainfo " + OUT)
        assert ret == 0, out
        assert "WhatsApp version: 2.24.1.1" in out
        assert "The last two numbers of the user's Jid: 42" in out
        assert "Features: [5, 7, 13]" in out


class TestReference:
    """--reference copies the props off a real backup, which is the documented workflow."""

    def teardown_method(self):
        cleanup()

    def test_a_crypt15_reference_reproduces_the_original(self):
        out, ret = Propen("waencrypt --reference tests/res/msgstore.db.crypt15 {} {} {}"
                          .format(KEY15, PLAIN, OUT))
        assert ret == 0, out
        if CLASSIC_ZLIB:
            assert cmp_files(OUT, "tests/res/msgstore.db.crypt15")
        out, ret = Propen("wadecrypt {} {} {}".format(KEY15, OUT, ROUNDTRIP))
        assert ret == 0, out
        assert cmp_files(ROUNDTRIP, PLAIN)

    @pytest.mark.xfail(strict=True, reason=(
        "Props(v_features=...) never sets max_feature, so get_features() -- which "
        "Database14.encrypt calls and Database15.encrypt does not -- raises AttributeError. "
        "Remove this marker when props.py is fixed."))
    def test_a_crypt14_reference_works_too(self):
        out, ret = Propen("waencrypt --type 14 --reference tests/res/msgstore.db.crypt14 "
                          "{} {} {}".format(KEY14, PLAIN, OUT))
        assert ret == 0, out


class TestExistingOutput:
    """
    waencrypt refuses to write over a file that is already there.

    The output used to be an argparse.FileType('wb'), which opens it while the arguments are
    still being parsed: pointing the tool at an existing backup emptied it before a single
    check had run, and a run that then failed left nothing behind.
    """

    def teardown_method(self):
        cleanup()

    def write_something(self):
        with open(OUT, 'wb') as f:
            f.write(b'PRECIOUS')

    def test_an_existing_output_stops_the_run(self):
        self.write_something()
        out, ret = Propen("waencrypt {} {} {}".format(KEY15, PLAIN, OUT))
        assert ret != 0
        assert "output file already exists" in out
        with open(OUT, 'rb') as f:
            assert f.read() == b'PRECIOUS'

    def test_yes_overwrites_it(self):
        self.write_something()
        out, ret = Propen("waencrypt --yes {} {} {}".format(KEY15, PLAIN, OUT))
        assert ret == 0, out
        out, ret = Propen("wadecrypt {} {} {}".format(KEY15, OUT, ROUNDTRIP))
        assert ret == 0, out
        assert cmp_files(ROUNDTRIP, PLAIN)

    def test_a_run_that_fails_leaves_the_output_alone(self):
        # Even with --yes: the file is opened only once there is something to write to it.
        self.write_something()
        out, ret = Propen("waencrypt --yes tests/res/test.json {} {}".format(PLAIN, OUT))
        assert ret != 0
        with open(OUT, 'rb') as f:
            assert f.read() == b'PRECIOUS'


class TestFailures:
    def teardown_method(self):
        cleanup()

    def test_a_file_that_is_not_a_key_fails(self):
        out, ret = Propen("waencrypt tests/res/test.json {} {}".format(PLAIN, OUT))
        assert ret != 0
        assert "not a valid Java object" in out

    def test_a_reference_that_is_not_a_backup_fails(self):
        out, ret = Propen("waencrypt --reference tests/res/test.json {} {} {}"
                          .format(KEY15, PLAIN, OUT))
        assert ret != 0
        assert "does not look like a crypt12, 14 or 15 database" in out
