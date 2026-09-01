"""
waencrypt, which had no invocation test at all despite being the tool marked beta.

Everything is checked by round-tripping through wadecrypt rather than by comparing bytes:
zlib-ng (CPython 3.14+ on Windows) compresses differently, so only the plaintext is stable
across platforms. The one byte-for-byte check is guarded on that.
"""

import os.path
import zlib
from hashlib import md5

import pytest

from tests.utils.utils import Propen, cmp_files, rm_if_found

KEY15 = "tests/res/encrypted_backup.key"
KEY14 = "tests/res/key"
PLAIN = "tests/res/msgstore.db"
OUT = "waencrypt-test-out.crypt"
ROUNDTRIP = "waencrypt-test-roundtrip.db"

CLASSIC_ZLIB = "zlib-ng" not in zlib.ZLIB_VERSION and "zlib-ng" not in zlib.ZLIB_RUNTIME_VERSION


def cleanup():
    rm_if_found(OUT)
    rm_if_found(ROUNDTRIP)


def roundtrip(key: str, *extra: str) -> str:
    """Encrypts the reference database, decrypts it back, and returns wadecrypt's output."""
    out, ret = Propen(["waencrypt", *extra, key, PLAIN, OUT])
    assert ret == 0, out
    out, ret = Propen(f"wadecrypt {key} {OUT} {ROUNDTRIP}")
    assert ret == 0, out
    return out


class TestRoundTrips:
    def teardown_method(self):
        cleanup()

    @pytest.mark.parametrize(
        "key, type_",
        [
            pytest.param(KEY15, "15", id="crypt15"),
            pytest.param(KEY14, "14", id="crypt14"),
            pytest.param(KEY14, "12", id="crypt12"),
        ],
    )
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
        out, ret = Propen(
            [
                "waencrypt",
                "--enable-features",
                "5",
                "7",
                "13",
                "--type",
                "15",
                "--jid",
                "42",
                "--wa-version",
                "2.24.1.1",
                "--max-feature",
                "37",
                KEY15,
                PLAIN,
                OUT,
            ]
        )
        assert ret == 0, out
        out, ret = Propen("wainfo " + OUT)
        assert ret == 0, out
        assert "WhatsApp version: 2.24.1.1" in out
        assert "The last two numbers of the user's Jid: 42" in out
        assert "Features: [5, 7, 13]" in out


def with_unknown_header_field(source: str, dest: str, field: bytes = b"\x30\x03"):
    """
    Copies a backup, adding a protobuf field the schema does not model to its header.

    Real 2.26 backups carry exactly this: field 6, varint, value 3. The header is rebuilt
    around it -- the size byte grows, and the trailing md5 covers the header, so it has to be
    recomputed -- but the ciphertext and its authentication tag are untouched.
    """
    raw = open(source, "rb").read()
    size = raw[0]
    offset = 2 if raw[1] == 1 else 1
    proto = raw[offset : offset + size] + field
    body = raw[offset + size : -16]  # ciphertext and tag, without the md5
    header = bytes([len(proto)]) + raw[1:offset] + proto
    with open(dest, "wb") as f:
        f.write(header + body + md5(header + body).digest())


def without_feature_table_flag(source: str, dest: str):
    """
    Rewrites a backup's header with every migration flag cleared -- the shape a non-msgstore
    backup (wa.db, chatsettingsbackup and the rest) actually has.

    There never was a separate byte marking a header as "no feature table": the header's size
    prefix is a protobuf varint on its own, and a header with nothing set is just smaller
    content, sized the same way any other header is. What looked like that byte was its
    mandatory varint continuation for any size in [128, 255], present or not regardless of
    features.
    """
    import io

    from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
    from wa_crypt_tools.lib.utils import encode_varint

    raw = open(source, "rb").read()
    stream = io.BufferedReader(io.BytesIO(raw))
    db = DatabaseFactory.from_file(stream)
    header_len = stream.tell()
    body = raw[header_len:-16]
    for field in db.prefix.backup_metadata.DESCRIPTOR.fields:
        if field.type == field.TYPE_BOOL:
            db.prefix.backup_metadata.ClearField(field.name)
    serialized = db.prefix.SerializeToString()
    header = encode_varint(len(serialized)) + serialized
    with open(dest, "wb") as f:
        f.write(header + body + md5(header + body).digest())


class TestReference:
    """--reference copies the props off a real backup, which is the documented workflow."""

    def teardown_method(self):
        cleanup()

    def test_a_crypt15_reference_reproduces_the_original(self):
        # The fixture is a 2.22 backup, compressed at level 1, and no -c is passed here:
        # reproducing it byte-for-byte means the level has to come off the reference too.
        out, ret = Propen(f"waencrypt --reference tests/res/msgstore.db.crypt15 {KEY15} {PLAIN} {OUT}")
        assert ret == 0, out
        if CLASSIC_ZLIB:
            assert cmp_files(OUT, "tests/res/msgstore.db.crypt15")
        out, ret = Propen(f"wadecrypt {KEY15} {OUT} {ROUNDTRIP}")
        assert ret == 0, out
        assert cmp_files(ROUNDTRIP, PLAIN)

    def test_an_unknown_header_field_is_carried_through(self, tmp_path):
        # WhatsApp puts a field in the header that this schema does not model, and rebuilding
        # the header from Props alone drops it. Those two bytes are the entire difference
        # between a re-encryption that merely works and one that reproduces the original.
        ref = str(tmp_path / "unknown-field.crypt15")
        with_unknown_header_field("tests/res/msgstore.db.crypt15", ref)
        out, ret = Propen(["waencrypt", "--reference", ref, KEY15, PLAIN, OUT])
        assert ret == 0, out
        if CLASSIC_ZLIB:
            assert cmp_files(OUT, ref)

    def test_a_reference_without_a_feature_table_stays_without_one(self, tmp_path):
        # Database15 used to write an extra byte whenever it believed the source was a
        # msgstore, so a non-msgstore reference came back one byte longer than it went in.
        # The size prefix is a plain protobuf varint now, with nothing extra to get wrong.
        ref = str(tmp_path / "no-feature-table.crypt15")
        without_feature_table_flag("tests/res/msgstore.db.crypt15", ref)
        out, ret = Propen(["waencrypt", "--reference", ref, KEY15, PLAIN, OUT])
        assert ret == 0, out
        if CLASSIC_ZLIB:
            assert cmp_files(OUT, ref)

    def test_a_crypt14_reference_works_too(self):
        # This used to raise AttributeError out of Props.max_feature, because encrypt() asked
        # the props whether to write the feature table flag and props built from a reference
        # never set it. It reads the flag off the reference now and never asks.
        out, ret = Propen(f"waencrypt --type 14 --reference tests/res/msgstore.db.crypt14 {KEY14} {PLAIN} {OUT}")
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
        with open(OUT, "wb") as f:
            f.write(b"PRECIOUS")

    def test_an_existing_output_stops_the_run(self):
        self.write_something()
        out, ret = Propen(f"waencrypt {KEY15} {PLAIN} {OUT}")
        assert ret != 0
        assert "output file already exists" in out
        with open(OUT, "rb") as f:
            assert f.read() == b"PRECIOUS"

    def test_yes_overwrites_it(self):
        self.write_something()
        out, ret = Propen(f"waencrypt --yes {KEY15} {PLAIN} {OUT}")
        assert ret == 0, out
        out, ret = Propen(f"wadecrypt {KEY15} {OUT} {ROUNDTRIP}")
        assert ret == 0, out
        assert cmp_files(ROUNDTRIP, PLAIN)

    def test_a_run_that_fails_leaves_the_output_alone(self):
        # Even with --yes: the file is opened only once there is something to write to it.
        self.write_something()
        _out, ret = Propen(f"waencrypt --yes tests/res/test.json {PLAIN} {OUT}")
        assert ret != 0
        with open(OUT, "rb") as f:
            assert f.read() == b"PRECIOUS"


class TestFailures:
    def teardown_method(self):
        cleanup()

    def test_a_file_that_is_not_a_key_fails(self):
        out, ret = Propen(f"waencrypt tests/res/test.json {PLAIN} {OUT}")
        assert ret != 0
        assert "not a valid Java object" in out

    def test_a_reference_that_is_not_a_backup_fails(self):
        out, ret = Propen(f"waencrypt --reference tests/res/test.json {KEY15} {PLAIN} {OUT}")
        assert ret != 0
        assert "does not look like a crypt12, 14 or 15 database" in out


class TestCompressionLevel:
    """
    The level was hardcoded to 1, which is what WhatsApp itself used at the time. Current
    WhatsApp compresses at 9 -- a real 2.26 msgstore re-encrypted at 1 came out 3.5% larger
    than the original, and at 9 landed within 4 bytes of it. Both levels have to stay
    reachable, so the level is an option and 9 is only the default.
    """

    REF = "waencrypt-test-reference.crypt15"

    def teardown_method(self):
        cleanup()
        rm_if_found(self.REF)

    def size_at(self, *extra: str) -> int:
        out, ret = Propen(["waencrypt", *extra, KEY15, PLAIN, OUT])
        assert ret == 0, out
        size = os.path.getsize(OUT)
        rm_if_found(OUT)
        return size

    def test_nine_compresses_better_than_one(self):
        assert self.size_at("-c", "9") < self.size_at("-c", "1")

    def test_the_default_is_nine(self):
        assert self.size_at() == self.size_at("-c", "9")

    @pytest.mark.parametrize("level", ["1", "6", "9"])
    def test_every_level_still_round_trips(self, level):
        roundtrip(KEY15, "-c", level)
        assert cmp_files(PLAIN, ROUNDTRIP)

    @pytest.mark.parametrize("level", ["-1", "10", "abc"])
    def test_a_level_outside_the_range_is_refused(self, level):
        out, ret = Propen(["waencrypt", "-c", level, KEY15, PLAIN, OUT])
        assert ret != 0, out

    def test_the_level_is_taken_from_the_reference(self):
        # --reference exists to reproduce a backup, and the level is part of that: a
        # reference built at 1 has to come back out at 1, not at the default of 9.
        out, ret = Propen(["waencrypt", "-c", "1", KEY15, PLAIN, self.REF])
        assert ret == 0, out
        out, ret = Propen(["waencrypt", "--reference", self.REF, KEY15, PLAIN, OUT])
        assert ret == 0, out
        assert os.path.getsize(OUT) == os.path.getsize(self.REF)

    def test_an_explicit_level_beats_the_reference(self):
        out, ret = Propen(["waencrypt", "-c", "1", KEY15, PLAIN, self.REF])
        assert ret == 0, out
        out, ret = Propen(["waencrypt", "-c", "9", "--reference", self.REF, KEY15, PLAIN, OUT])
        assert ret == 0, out
        assert os.path.getsize(OUT) < os.path.getsize(self.REF)

    def test_no_compress_ignores_the_level(self):
        # --no-compress writes the plaintext through untouched, so a level alongside it
        # cannot silently start compressing.
        out, ret = Propen(["waencrypt", "--no-compress", "-c", "9", KEY15, PLAIN, OUT])
        assert ret == 0, out
        assert os.path.getsize(OUT) > os.path.getsize(PLAIN)
