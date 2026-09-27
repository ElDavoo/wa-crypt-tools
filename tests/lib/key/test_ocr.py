"""
Reading the 64-digit key off a screenshot.

Two kinds of test live here, and the split is deliberate. Everything that decides *which
boxes on the screen are the key* is a pure function over Tesseract's output, so it is tested
against hand-written box dictionaries and runs everywhere, with or without OCR installed --
which matters, because that is where all the logic is. Only the handful of tests that assert
a real image reads back as a real key need Tesseract, and those are skipped when the optional
extra is missing.

The screenshots under tests/res/ are:

- key-screenshot-android-2.26.png    a real phone, the "save this key" screen
- key-screenshot-confirm-2.26.png    the same phone, the "have you saved it?" confirmation,
                                     with different prose around the same key
- key-screenshot-synthetic{,-dark}   the same phone's glyphs rearranged to spell the key of
                                     tests/res/encrypted_backup.key, in light and dark mode
                                     (see utils/make_key_screenshot.py)
"""

from __future__ import annotations

import re
from collections import Counter

import pytest

from tests.utils.utils import requires_ocr
from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key import ocr

ANDROID = "tests/res/key-screenshot-android-2.26.png"
CONFIRM = "tests/res/key-screenshot-confirm-2.26.png"
SYNTHETIC = "tests/res/key-screenshot-synthetic.png"
SYNTHETIC_DARK = "tests/res/key-screenshot-synthetic-dark.png"

#: What the two real screenshots show.
PHONE_KEY = "e3acf1798c4e7e0e0d24c2a498d6fe5967517526bc0db813353feebb302cb9de"
#: What the synthetic ones show: the root key of tests/res/encrypted_backup.key.
FIXTURE_KEY = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"


def boxes(*rows, left=100, top=100, width=112, height=34, step=230, line=82):
    """
    An image_to_data dict laying `rows` out on a grid, one word per column.

    Sizes default to the real screenshot's, because the row clustering is measured in line
    heights and the column snapping in group widths -- made-up numbers would test made-up
    tolerances.
    """
    data = {key: [] for key in ("text", "left", "top", "width", "height")}
    for r, row in enumerate(rows):
        for c, word in enumerate(row):
            data["text"].append(word)
            data["left"].append(left + c * step)
            data["top"].append(top + r * line)
            data["width"].append(width)
            data["height"].append(height)
    return data


def read(data):
    """The keys candidate_runs would offer for a set of boxes, as strings."""
    return ["".join(g["text"] for g in groups) for groups in ocr.candidate_runs(ocr.rows_from_boxes(data))]


class TestNormalize:
    @pytest.mark.parametrize(
        "word, expected",
        [
            ("e3ac", "e3ac"),
            ("E3AC", "e3ac"),
            ("bcoOd", "bc00d"),  # the o/O the real screenshot actually produces
            ("39cl", "39c1"),
            ("Il", "11"),
            ("SBENT", "5ben7"),
        ],
    )
    def test_confusions_are_undone(self, word, expected):
        assert ocr.normalize(word) == expected

    def test_b_is_not_remapped_to_8(self):
        # 'b' is a hex digit in its own right, so a b/8 confusion cannot be told from a
        # correct read. Guessing here would corrupt the grid detection, not improve it.
        assert ocr.normalize("b813") == "b813"

    @pytest.mark.parametrize("word", ["18:46:08", "copia.", "telefono,", "WhatsApp", "grado"])
    def test_prose_and_punctuation_are_not_hex(self, word):
        assert not ocr.is_hex_word(word)

    @pytest.mark.parametrize("word", ["cafe", "beef", "1", "la", "Se"])
    def test_words_that_happen_to_be_hex_are_hex(self, word):
        # These are why a single hex-looking word cannot pick out the key: real prose is full
        # of them. It takes a whole row of them, in a grid, to mean anything.
        assert ocr.is_hex_word(word)


class TestRows:
    def test_words_are_grouped_by_line_and_ordered_left_to_right(self):
        data = boxes(["6751", "7526", "bc0d", "b813"], ["353f", "eebb", "302c", "b9de"])
        rows = ocr.rows_from_boxes(data)
        assert [[w["text"] for w in row] for row in rows] == [
            ["6751", "7526", "bc0d", "b813"],
            ["353f", "eebb", "302c", "b9de"],
        ]

    def test_a_wobbling_baseline_stays_one_row(self):
        data = boxes(["e3ac", "f179"])
        data["top"][1] += 3  # what a real row actually does
        assert len(ocr.rows_from_boxes(data)) == 1

    def test_empty_words_are_dropped(self):
        # image_to_data returns a blank entry per block and per line, not just per word.
        data = boxes(["e3ac", "", "  ", "f179"])
        assert [w["text"] for w in ocr.rows_from_boxes(data)[0]] == ["e3ac", "f179"]

    def test_no_words_at_all(self):
        assert ocr.rows_from_boxes({"text": [], "left": [], "top": [], "width": [], "height": []}) == []


class TestCandidateRuns:
    def test_four_rows_of_four_groups(self):
        found = read(boxes(*[["e3ac", "f179", "8c4e", "7e0e"]] * 4))
        # Offered group by group (16 boxes) and row by row (4), finest first.
        assert len(found[0]) == 64 and len(found) >= 2

    def test_one_row_of_sixteen_groups(self):
        assert read(boxes(["ab12"] * 16, width=40, step=45))[0] == "ab12" * 16

    def test_eight_rows_of_two_groups(self):
        assert read(boxes(*[["abcd", "1234"]] * 8, width=200, step=260))[0] == "abcd1234" * 8

    def test_prose_alone_yields_nothing(self):
        assert read(boxes(["Save", "this", "key.", "WhatsApp"], ["cannot", "recover", "the", "backup."])) == []

    def test_prose_around_the_grid_is_left_out(self):
        data = boxes(
            ["Encryption", "key", "is", "below"], *[["e3ac", "f179", "8c4e", "7e0e"]] * 4, ["Backed", "up", "at", "08:15:42"]
        )
        assert read(data)[0] == "e3acf1798c4e7e0e" * 4

    def test_a_row_read_too_badly_to_be_hex_is_kept_for_its_geometry(self):
        # The real screenshot's fourth row: "353f" comes back as "SBENT". The row cannot pass
        # a hex test and must be part of the grid anyway, or there is no grid. What is asserted
        # is the count of boxes, not their text -- pass 1's text for that group is wrong by
        # definition here, and pass 2 is what will read it.
        data = boxes(
            ["e3ac", "f179", "8c4e", "7e0e"],
            ["0d24", "c2a4", "98d6", "fe59"],
            ["6751", "7526", "bc0d", "b813"],
            ["SBENT", "eebb", "302c", "bode"],
        )
        assert len(ocr.candidate_runs(ocr.rows_from_boxes(data))[0]) == 16

    def test_a_group_split_in_two_is_snapped_back_together(self):
        # "bb6f" coming back as "bbb" and "f" gives a row five groups wide. Without snapping
        # it to the columns the block has 17 groups, which divides nothing.
        data = boxes(*[["e401", "bb6f", "0e1b", "8ee2"]] * 4)
        data["text"][1] = "bbb"
        data["width"][1] = 84
        for key, value in (("text", "f"), ("left", 100 + 230 + 88), ("top", 100), ("width", 24), ("height", 34)):
            data[key].insert(2, value)
        assert len(read(data)[0]) == 64

    def test_a_block_that_cannot_be_split_evenly_is_rejected(self):
        # Three groups per row over three rows is nine boxes, and nine divides neither 64 nor
        # any row length that would make 64.
        assert read(boxes(*[["abc", "def", "123"]] * 3)) == []

    def test_the_same_boxes_are_only_offered_once(self):
        found = ocr.candidate_runs(ocr.rows_from_boxes(boxes(*[["e3ac", "f179"]] * 8)))
        where = [tuple((g["left"], g["top"], g["width"]) for g in c) for c in found]
        assert len(where) == len(set(where))


class TestLooksLikeImage:
    @pytest.mark.parametrize(
        "head",
        [
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 4,
            b"\xff\xd8\xff\xe0" + b"\x00" * 8,
            b"GIF89a" + b"\x00" * 6,
            b"BM" + b"\x00" * 10,
            b"RIFF\x00\x00\x00\x00WEBP",
            b"\x00\x00\x00\x18ftypheic",
            b"\x00\x00\x00\x18ftypavif",
        ],
        ids=["png", "jpeg", "gif", "bmp", "webp", "heic", "avif"],
    )
    def test_image_magic_is_recognised(self, tmp_path, head):
        path = tmp_path / "shot"  # no extension: the bytes are what decide
        path.write_bytes(head)
        assert ocr.looks_like_image(path)

    @pytest.mark.parametrize(
        "path", ["tests/res/encrypted_backup.key", "tests/res/key", "tests/res/test.json", "tests/res/msgstore.db.crypt15"]
    )
    def test_the_files_this_must_not_intercept(self, path):
        assert not ocr.looks_like_image(path)

    def test_a_missing_file_is_not_an_image_and_does_not_raise(self):
        # new() calls this before opening anything; reporting the missing file is the job of
        # whatever tries to read it next, which knows whether it was meant to be a key or hex.
        assert not ocr.looks_like_image("tests/res/there-is-no-such-file")

    def test_a_truncated_file_is_not_an_image(self, tmp_path):
        path = tmp_path / "shot"
        path.write_bytes(b"\x00\x00\x00\x18ftyp")  # the brand never arrives
        assert not ocr.looks_like_image(path)


class TestSingleThreaded:
    def test_it_pins_and_then_restores(self, monkeypatch):
        monkeypatch.delenv("OMP_THREAD_LIMIT", raising=False)
        import os

        with ocr.single_threaded():
            assert os.environ["OMP_THREAD_LIMIT"] == "1"
        assert "OMP_THREAD_LIMIT" not in os.environ

    def test_a_setting_of_the_callers_own_is_left_alone(self, monkeypatch):
        import os

        monkeypatch.setenv("OMP_THREAD_LIMIT", "8")
        with ocr.single_threaded():
            assert os.environ["OMP_THREAD_LIMIT"] == "8"
        assert os.environ["OMP_THREAD_LIMIT"] == "8"


class TestReadingRealScreenshots:
    """
    The end of the argument: real images in, the right 64 digits out.

    These are the slow tests in the suite -- a screenshot is read at two granularities and
    six crop offsets each, so twelve Tesseract invocations, about twenty seconds.
    """

    def setup_method(self):
        requires_ocr()

    def test_a_real_screenshot_reads_exactly(self):
        assert ocr.key_from_image(ANDROID) == PHONE_KEY

    def test_the_confirmation_screen_reads_the_same_key(self):
        # Same key, different screen: more prose above it, a second button below. If the
        # reader were keying off anything but the grid itself this would not survive.
        assert ocr.key_from_image(CONFIRM) == PHONE_KEY

    def test_dark_mode(self):
        assert ocr.key_from_image(SYNTHETIC_DARK) == FIXTURE_KEY

    def test_a_picture_with_no_key_in_it_says_so(self, tmp_path):
        from PIL import Image

        path = tmp_path / "blank.png"
        Image.new("RGB", (600, 400), (255, 255, 255)).save(path)
        with pytest.raises(InvalidKeyError, match="No block of hex digits"):
            ocr.key_from_image(path)

    def test_a_file_that_is_not_a_readable_image_says_so(self, tmp_path):
        path = tmp_path / "broken.png"
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"not actually a png")
        with pytest.raises(InvalidKeyError, match="Could not read the image"):
            ocr.key_from_image(path)


class TestWithoutTheExtra:
    def test_a_missing_tesseract_binary_names_the_package_to_install(self, monkeypatch):
        # The other half of the extra: the Python packages import fine and the program they
        # shell out to is not there. pytesseract reports that as a TesseractNotFoundError,
        # which subclasses OSError -- so without its own branch it came back as "could not
        # read the image", blaming the screenshot for a missing binary.
        pytest.importorskip("pytesseract", reason="needs the [ocr] extra")
        import pytesseract

        ocr._read.cache_clear()

        def not_installed(*_args, **_kwargs):
            raise pytesseract.TesseractNotFoundError()

        monkeypatch.setattr(pytesseract, "image_to_data", not_installed)
        try:
            with pytest.raises(InvalidKeyError, match="tesseract program is not installed"):
                ocr.key_from_image(ANDROID)
        finally:
            ocr._read.cache_clear()

    def test_the_error_names_the_extra_to_install(self, monkeypatch):
        # What someone who never installed it sees. Hiding the import is the only way to
        # reach this on a machine where it *is* installed -- and the read cache has to go
        # with it, or an earlier test having read this screenshot means the import that is
        # supposed to fail is never reached at all.
        import builtins

        real_import = builtins.__import__
        ocr._read.cache_clear()

        def missing(name, *args, **kwargs):
            if name == "pytesseract":
                raise ModuleNotFoundError("No module named 'pytesseract'", name="pytesseract")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", missing)
        try:
            with pytest.raises(InvalidKeyError, match=r"wa-crypt-tools\[ocr\]"):
                ocr.key_from_image(ANDROID)
        finally:
            ocr._read.cache_clear()


def reading(key, alternatives=(), span=4):
    """
    A Reading as read_cells would have built it, without needing Tesseract.

    `alternatives` are (cell, text, votes) triples: a losing read of that cell, and how many
    paddings gave it. Everything else was unanimous at six votes out of six.
    """
    cells = [Counter({key[i * span : (i + 1) * span]: 6}) for i in range(len(key) // span)]
    for cell, text, votes in alternatives:
        cells[cell][key[cell * span : (cell + 1) * span]] = 6 - votes
        cells[cell][text] = votes
    return ocr.Reading(key=key, cells=tuple(cells), span=span)


class TestAlternativeKeys:
    """
    The guesses made when the key read off the screenshot turns out not to decrypt anything.

    `_read` is patched out throughout: what is being tested is the guessing, and running OCR
    to get to it would add twenty seconds and a Tesseract dependency for no coverage.
    """

    KEY = FIXTURE_KEY

    def patch(self, monkeypatch, *readings):
        monkeypatch.setattr(ocr, "_read", lambda file: tuple(readings))

    def test_every_guess_is_a_64_digit_hex_key(self, monkeypatch):
        self.patch(monkeypatch, reading(self.KEY))
        for guess in ocr.alternative_keys("screenshot.png", limit=3000):
            assert re.fullmatch(r"[0-9a-f]{64}", guess), guess

    def test_the_key_that_was_read_is_never_guessed_again(self, monkeypatch):
        self.patch(monkeypatch, reading(self.KEY))
        assert self.KEY not in set(ocr.alternative_keys("screenshot.png", limit=3000))

    def test_no_guess_is_repeated(self, monkeypatch):
        self.patch(monkeypatch, reading(self.KEY))
        guesses = list(ocr.alternative_keys("screenshot.png", limit=4000))
        assert len(guesses) == len(set(guesses))

    def test_any_single_wrong_digit_is_guessed(self, monkeypatch):
        # The guarantee the feature rests on: 64 positions by 15 other digits, all of them,
        # regardless of what the vote or the lookalike table expected. 960 guesses, well
        # inside the budget.
        self.patch(monkeypatch, reading(self.KEY))
        guesses = set(ocr.alternative_keys("screenshot.png", limit=2000))
        for position in range(64):
            for digit in "0123456789abcdef":
                if digit != self.KEY[position]:
                    variant = self.KEY[:position] + digit + self.KEY[position + 1 :]
                    assert variant in guesses, f"missed {digit} at {position}"

    def test_a_losing_vote_is_guessed_before_anything_else(self, monkeypatch):
        # Cell 2 read "a148" four times and "a1a8" twice. That is real evidence about this
        # image and has to outrank every guess made from a table.
        self.patch(monkeypatch, reading(self.KEY, [(2, "a1a8", 2)]))
        guesses = list(ocr.alternative_keys("screenshot.png", limit=50))
        assert guesses[0] == self.KEY[:8] + "a1a8" + self.KEY[12:]

    def test_a_closer_vote_is_guessed_before_a_more_lopsided_one(self, monkeypatch):
        self.patch(monkeypatch, reading(self.KEY, [(1, "ab95", 1), (2, "a1a8", 3)]))
        guesses = list(ocr.alternative_keys("screenshot.png", limit=50))
        assert guesses[0] == self.KEY[:8] + "a1a8" + self.KEY[12:]
        assert guesses[1] == self.KEY[:4] + "ab95" + self.KEY[8:]

    def test_the_other_granularity_is_guessed_whole_and_digit_by_digit(self, monkeypatch):
        # Reading row by row disagreed in one digit; both that whole key and the single
        # change that produces it are worth trying.
        other = self.KEY[:31] + "d" + self.KEY[32:]
        self.patch(monkeypatch, reading(self.KEY), reading(other, span=16))
        assert other in set(ocr.alternative_keys("screenshot.png", limit=200))

    def test_the_limit_is_honoured(self, monkeypatch):
        self.patch(monkeypatch, reading(self.KEY))
        assert len(list(ocr.alternative_keys("screenshot.png", limit=7))) == 7

    def test_two_lookalike_digits_at_once_are_reached(self, monkeypatch):
        # a -> 4 and 5 -> b, both confusions Tesseract really makes, in one key. Two digits
        # are not guaranteed the way one is -- the whole two-digit space is 450,000 guesses
        # and three minutes -- but a pair of lookalikes is what the fourth tier is for.
        assert self.KEY[4:6] == "a5", "fixture key changed; pick two other positions"
        both = self.KEY[:4] + "4b" + self.KEY[6:]
        self.patch(monkeypatch, reading(self.KEY))
        assert both in set(ocr.alternative_keys("screenshot.png"))

    def test_a_key_needing_three_changes_is_not_promised(self, monkeypatch):
        # Stated so the limit is deliberate rather than discovered: past two digits this
        # stops looking, and wadecrypt says so instead of implying it searched everything.
        self.patch(monkeypatch, reading(self.KEY))
        three = "4b4" + self.KEY[3:]
        assert three not in set(ocr.alternative_keys("screenshot.png"))
