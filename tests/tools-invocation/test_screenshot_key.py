"""
Passing a screenshot of the key where the tools expect the key.

The whole point of issue #14 is that no new flag appears anywhere: the screenshot goes in the
same argument the key file goes in, and KeyFactory works out which it is. These run the
console scripts, so they are the only tests that prove that holds through argparse and the
entry points rather than only in the library.

tests/res/key-screenshot-synthetic.png shows the key of tests/res/encrypted_backup.key, so a
decryption driven by it has to produce exactly tests/res/msgstore.db -- which makes this an
end-to-end test of the feature and not just of the reader.
"""

from os.path import exists

import pytest

from tests.utils.utils import Propen, cmp_files, requires_ocr, rm_if_found

SCREENSHOT = "tests/res/key-screenshot-synthetic.png"
DARK = "tests/res/key-screenshot-synthetic-dark.png"
OUT = "screenshot-key-out.db"


@pytest.fixture
def _needs_ocr():
    """Applied per class, not autouse: only some of what is here goes near OCR."""
    requires_ocr()


@pytest.mark.usefixtures("_needs_ocr")
class TestScreenshotAsKey:
    def test_wadecrypt_takes_a_screenshot_as_the_key(self):
        # Both assertions in one run on purpose: a read is about twenty seconds, and doing it
        # twice to check two things about the same run buys nothing.
        try:
            out, ret = Propen(f"wadecrypt -v {SCREENSHOT} tests/res/msgstore.db.crypt15 {OUT}")
            assert ret == 0, out
            assert cmp_files(OUT, "tests/res/msgstore.db")
            # Under -v, and only under -v: the key is a means to an end, and the tool checks
            # it against the backup itself rather than asking the user to.
            assert "Key read from the screenshot: 6730 a595 a148 4d0c" in out
        finally:
            rm_if_found(OUT)

    def test_wainfo_k_prints_the_key_read_off_a_screenshot(self):
        out, ret = Propen("wainfo -k " + DARK)
        assert ret == 0, out
        assert "Key15(key: 6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017)" in out

    def test_a_picture_that_is_not_a_key_screen_fails_cleanly(self):
        # A real PNG with no key in it -- the project's own logo. Not a traceback, and not
        # "the keyfile is not a valid Java object" either: it was recognised as an image, so
        # the complaint has to be about what is in the image.
        try:
            out, ret = Propen("wadecrypt 1000.png tests/res/msgstore.db.crypt15 " + OUT)
            assert ret != 0
            assert "Traceback" not in out
            assert "No block of hex digits" in out
        finally:
            rm_if_found(OUT)


#: What key-screenshot-android-2.26.png reads back as.
PHONE_KEY = "e3acf1798c4e7e0e0d24c2a498d6fe5967517526bc0db813353feebb302cb9de"
ANDROID = "tests/res/key-screenshot-android-2.26.png"
NEAR_MISS = "near-miss.db.crypt15"


def backup_encrypted_with(key: str):
    """
    A copy of tests/res/msgstore.db encrypted under `key`.

    The tests below use this to stage the failure the recovery exists for, from the only
    direction that is reproducible. Making OCR misread a screenshot on demand is not
    something that can be pinned down -- it depends on the Tesseract build -- but a *backup*
    whose real key differs from the screenshot by one digit puts the code in exactly the same
    position: the key it read does not decrypt this file, and it has to work out why.
    """
    out, ret = Propen(f"waencrypt --reference tests/res/msgstore.db.crypt15 -y {key} tests/res/msgstore.db {NEAR_MISS}")
    assert ret == 0, out


@pytest.mark.usefixtures("_needs_ocr")
class TestRecoveringAMisreadDigit:
    def teardown_method(self):
        rm_if_found(NEAR_MISS)
        rm_if_found(OUT)

    def test_one_wrong_digit_is_found_and_the_backup_decrypts(self):
        # "8c4e" in the screenshot, "8c4d" on the phone -- the 4/d confusion Tesseract makes.
        real = PHONE_KEY[:11] + "d" + PHONE_KEY[12:]
        backup_encrypted_with(real)
        out, ret = Propen(f"wadecrypt -y {ANDROID} {NEAR_MISS} {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_the_repair_is_invisible_unless_asked_for(self):
        # The point of the whole thing: someone who hands over a screenshot wanted a
        # decryption, not a report on how their key was obtained. Nothing about the search
        # belongs on their screen when it worked.
        real = PHONE_KEY[:11] + "d" + PHONE_KEY[12:]
        backup_encrypted_with(real)
        out, ret = Propen(f"wadecrypt -y {ANDROID} {NEAR_MISS} {OUT}")
        assert ret == 0, out
        for noise in ("near miss", "misread", "does not decrypt", "tries", PHONE_KEY):
            assert noise not in out, f"{noise!r} should not be shown by default"

    def test_verbose_says_what_it_did(self):
        # ... and someone who asked why it took a moment gets the whole story.
        real = PHONE_KEY[:11] + "d" + PHONE_KEY[12:]
        backup_encrypted_with(real)
        out, ret = Propen(f"wadecrypt -v -y {ANDROID} {NEAR_MISS} {OUT}")
        assert ret == 0, out
        assert "does not decrypt this backup" in out
        assert "It was a digit or two out" in out
        assert real in out

    def test_two_wrong_digits_are_found_too(self):
        # a -> 4 and 5 -> b at once. Not guaranteed the way one digit is, but reached.
        real = PHONE_KEY[:11] + "d" + PHONE_KEY[12:31] + "b" + PHONE_KEY[32:]
        backup_encrypted_with(real)
        out, ret = Propen(f"wadecrypt -y {ANDROID} {NEAR_MISS} {OUT}")
        assert ret == 0, out
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_a_key_that_cannot_be_repaired_blames_the_reader(self):
        # The one thing worth interrupting anyone about. The key is 64 digits the user can
        # see with their own eyes; the program is the part that got them wrong, and the way
        # out is to type them in. Saying "your backup is corrupt" here would send them off
        # after the wrong problem entirely.
        backup_encrypted_with("ab" * 32)
        out, ret = Propen(f"wadecrypt -y {ANDROID} {NEAR_MISS} {OUT}")
        assert ret != 0
        assert "Could not read the key from the screenshot" in out
        assert "Transcribe the 64 digits" in out
        assert "Traceback" not in out
        assert not exists(OUT)

    def test_a_key_file_is_never_second_guessed(self):
        # The search only ever runs for a key that came off a screenshot. A key file that
        # does not match must fail immediately, the way it always has.
        backup_encrypted_with("ab" * 32)
        out, ret = Propen(f"wadecrypt -y tests/res/encrypted_backup.key {NEAR_MISS} {OUT}")
        assert ret != 0
        assert "screenshot" not in out


class TestWhatTheWindowWouldSay:
    """
    wagui takes a screenshot wherever it takes a key file, and has to explain a failure in
    its own words. It dispatches on exception type, so the screenshot case needs its own.
    """

    def test_the_screenshot_failure_does_not_get_the_key_file_advice(self):
        # "Make sure you picked the key file and not the backup itself" is what a plain
        # InvalidKeyError means. Said about a screenshot it sends the user after a problem
        # they do not have -- they picked exactly the right file.
        pytest.importorskip("tkinter", reason="the GUI needs a Tk build")
        from wa_crypt_tools.gui import core
        from wa_crypt_tools.lib.errors import InvalidKeyError, ScreenshotKeyError

        assert issubclass(ScreenshotKeyError, InvalidKeyError)
        screenshot = core.friendly(ScreenshotKeyError("unreadable"))
        assert "screenshot" in screenshot
        assert "by hand" in screenshot
        assert "not the backup itself" not in screenshot
        # ... and the ordinary case is untouched.
        assert "not the backup itself" in core.friendly(InvalidKeyError("nope"))


#: The root key of tests/res/encrypted_backup.key, which tests/res/msgstore.db.crypt15 is under.
FIXTURE_KEY = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"
GROUPS = [FIXTURE_KEY[i : i + 4] for i in range(0, 64, 4)]


class TestATypedKeyIsRepairedToo:
    """
    The same repair for a key given on the command line rather than read off an image.

    This is the other half of the advice `wadecrypt` gives when OCR cannot manage a
    screenshot -- "transcribe the 64 digits by hand" -- and somebody transcribing 64 digits
    gets one wrong. No OCR is involved anywhere here, so these run everywhere.
    """

    def teardown_method(self):
        rm_if_found(OUT)

    @pytest.mark.parametrize(
        "name, typed",
        [
            ("one digit wrong", FIXTURE_KEY[:63] + "0"),
            ("two digits swapped", FIXTURE_KEY[:10] + FIXTURE_KEY[11] + FIXTURE_KEY[10] + FIXTURE_KEY[12:]),
            ("two groups swapped", "".join([GROUPS[0], GROUPS[2], GROUPS[1], *GROUPS[3:]])),
            ("grid read down the columns", "".join(GROUPS[c * 4 + r] for r in range(4) for c in range(4))),
        ],
    )
    def test_a_miscopied_key_still_decrypts(self, name, typed):
        out, ret = Propen(f"wadecrypt -y {typed} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret == 0, f"{name}: {out}"
        assert cmp_files(OUT, "tests/res/msgstore.db")

    def test_it_says_nothing_about_it(self):
        typed = FIXTURE_KEY[:63] + "0"
        out, ret = Propen(f"wadecrypt -y {typed} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret == 0, out
        for noise in ("near miss", "digit", "tries", FIXTURE_KEY):
            assert noise not in out, f"{noise!r} should not be shown by default"

    def test_verbose_says_what_it_did(self):
        typed = FIXTURE_KEY[:63] + "0"
        out, ret = Propen(f"wadecrypt -v -y {typed} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret == 0, out
        assert "does not decrypt this backup" in out
        assert FIXTURE_KEY in out

    def test_a_key_that_is_simply_wrong_still_fails_the_way_it_always_did(self):
        # No OCR to blame, and the user can see what they typed -- it may just be the key to
        # a different backup. So this says nothing of its own and lets the decryption fail on
        # its own terms.
        wrong = "ab" * 32
        out, ret = Propen(f"wadecrypt -y {wrong} tests/res/msgstore.db.crypt15 {OUT}")
        assert ret != 0
        assert "screenshot" not in out
        assert "Traceback" not in out
