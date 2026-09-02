"""
Reading the 64-digit root key off a screenshot of WhatsApp's "Encryption key" screen.

WhatsApp shows that key once and never again, so most people photograph it. Transcribing 64
hex digits by hand gets one wrong often enough to matter, and a key with one wrong digit
fails with exactly the same "the key does not match this backup" as a completely wrong key.

The hard part is not the OCR, it is telling the key apart from the prose around it. Two
properties of that screen make it tractable:

- The key is lowercase hex and nothing else. The prose around it is not.
- It is a *grid*: rows of equal-length groups, coming to 64 digits.

So the image is read twice, for two different purposes.

**Pass 1** (`_first_pass`, `rows_from_boxes`, `candidate_runs`) reads the whole image with no
character whitelist, and is used only for *geometry*. Its text is not trusted at all -- on
the fixture screenshot it reads "353f" as "SBENT" and "bc0d" as "bcoOd" -- but the box it
returns for those groups is still right, and boxes are all pass 1 is asked for.

**Pass 2** (`read_cells`) re-reads just those boxes with `tessedit_char_whitelist` set to the
16 hex digits. That is safe on a crop known to hold nothing but hex, and would be actively
harmful on the whole image, where it would force the surrounding prose into plausible hex and
manufacture rows that were never there.

Four things carry the accuracy, and every one of them was needed to read the fixtures:

- *Length is an oracle.* Every group is exactly 64/n digits, so a read of the wrong length is
  known-bad and gets discarded rather than used. This is what catches "8c4e" -> "8c4de".
- *The same crop is read at several paddings and the majority wins.* Nudging a crop by a few
  pixels changes the answer on exactly the glyphs that are marginal. On the fixture
  screenshot no single padding gets all 16 groups right, and the vote gets all 16.
- *Rows are snapped to the grid's columns* (`_snap`). Once the columns are known a row need
  not have been segmented correctly: "bb6f" coming back as "bbb" and "f" makes a five-wide
  row and a 17-group block, which divides nothing, so each word goes to the column it sits
  nearest and the column is read as one box.
- *The grid is read at two granularities and the answers compared.* Group-at-a-time and
  row-at-a-time fail differently, so their agreement is the only check there is on a misread
  that happens to come out the right length. When they disagree the caller is shown both
  rather than handed a guess.

None of that makes the result certain -- a b/8 confusion looks the same to every reading of
the same pixels -- so the key is always logged in the 4-digit groups the phone displays, for
the user to check against the picture.

Two things here look like micro-optimisations and are not. Every crop for one padding is
composed into a single stacked image and read in one call, because Tesseract reloads its
model per invocation: one call per crop is ~740ms, which turns a key read into 71 seconds.
And `single_threaded()` pins OMP_THREAD_LIMIT for the duration, because Tesseract built
against OpenMP is several times slower on this workload when left to use every core.
"""

import logging
import os
import re
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key.nearby import (
    GUESS_LIMIT,
    KEY_LENGTH,
    near_misses,
    one_digit,
    two_digits,
)

log = logging.getLogger(__name__)

#: Crop offsets, in pixels, that each group is read at before the vote.
PADDINGS = (2, 3, 4, 5, 6, 8)

#: Gap left around each crop when they are composed into one image for a single OCR call.
COMPOSE_GAP = 24

_HEX = re.compile(r"[0-9a-f]+")

# The confusions a rendered sans font actually produces, mapped onto the hex alphabet.
#
# This only ever decides *which boxes* are the key: no character of the returned key comes
# through here, because pass 2 re-reads every box under a whitelist that admits nothing but
# hex. So the cost of a wrong entry is a box wrongly kept or dropped, not a wrong digit --
# which is why it can afford to be generous with letters that are not hex digits themselves
# (o, l, i, s, z ...) and must not be with ones that are: mapping B to 8 would take a
# correctly-read 'b' and make it an 8 in the very comparison that picks the grid out.
_CONFUSIONS = str.maketrans(
    {
        "O": "0",
        "o": "0",
        "Q": "0",
        "l": "1",
        "I": "1",
        "|": "1",
        "i": "1",
        "Z": "2",
        "z": "2",
        "S": "5",
        "s": "5",
        "G": "6",
        "T": "7",
        "A": "a",
        "B": "b",
        "C": "c",
        "D": "d",
        "E": "e",
        "F": "f",
    }
)

# Magic bytes, not the extension: people rename screenshots, and a photo of the screen off an
# iPhone arrives as HEIC rather than PNG. WEBP and HEIF/AVIF are container formats whose
# marker sits at byte 8, after a length or a fourcc.
_MAGIC_PREFIXES = (
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",  # GIF
    b"BM",  # BMP
)
# ISO base media brands, which sit at byte 8 after a length and the 'ftyp' fourcc.
_ISOBMFF_BRANDS = (b"heic", b"heix", b"hevc", b"mif1", b"msf1", b"avif")


def looks_like_image(file) -> bool:
    """
    True if `file` is a file whose first bytes are an image's.

    Returns False rather than raising for anything unreadable, so that a caller can use it
    to choose a path and leave the reporting of a missing file to whoever opens it next.
    """
    try:
        with open(file, "rb") as f:
            head = f.read(12)
    except OSError:
        return False
    if head.startswith(_MAGIC_PREFIXES):
        return True
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return True
    return head[4:8] == b"ftyp" and head[8:12] in _ISOBMFF_BRANDS


def normalize(text: str) -> str:
    """Maps a word onto the hex alphabet: case-folded, with the usual OCR confusions undone."""
    return text.strip().translate(_CONFUSIONS).lower()


def is_hex_word(text: str) -> bool:
    """True if a word is hex digits and nothing else once normalized."""
    return bool(text) and _HEX.fullmatch(normalize(text)) is not None


def rows_from_boxes(data: dict) -> list[list[dict]]:
    """
    Clusters Tesseract's word boxes into visual rows, top to bottom, each left to right.

    `data` is what `pytesseract.image_to_data(output_type=DICT)` returns. Words are grouped
    by the vertical centre of their box rather than by Tesseract's own block/line numbering,
    which splits the key grid differently depending on how it reads the prose above it.

    Confidence is deliberately not filtered on: the group this reads worst is the one whose
    box is most needed, and on the fixture screenshot that group comes back at confidence 0.
    """
    words = [
        {
            "text": data["text"][i],
            "left": data["left"][i],
            "top": data["top"][i],
            "width": data["width"][i],
            "height": data["height"][i],
        }
        for i in range(len(data["text"]))
        if data["text"][i].strip()
    ]
    if not words:
        return []

    heights = sorted(w["height"] for w in words)
    # Half a line height: comfortably more than the couple of pixels a baseline wobbles
    # within one row, comfortably less than the gap between two rows.
    tolerance = max(heights[len(heights) // 2] * 0.6, 1)

    rows: list[list[dict]] = []
    current: list[dict] = []
    for word in sorted(words, key=lambda w: w["top"] + w["height"] / 2):
        centre = word["top"] + word["height"] / 2
        if current and centre - (current[-1]["top"] + current[-1]["height"] / 2) > tolerance:
            rows.append(sorted(current, key=lambda w: w["left"]))
            current = []
        current.append(word)
    rows.append(sorted(current, key=lambda w: w["left"]))
    return rows


#: How much of a row has to read as hex before the row is taken for part of the key grid.
#: Not all of it: on the fixture screenshot one group in four comes back as "SBENT".
SEED_RATIO = 0.75


def _merge(words: list[dict]) -> dict:
    """One box spanning several, for reading a whole row or a split group in one go."""
    left = min(w["left"] for w in words)
    top = min(w["top"] for w in words)
    return {
        "text": "".join(normalize(w["text"]) for w in words),
        "left": left,
        "top": top,
        "width": max(w["left"] + w["width"] for w in words) - left,
        "height": max(w["top"] + w["height"] for w in words) - top,
    }


def _seeds(row: list[dict]) -> bool:
    """True if enough of a row reads as hex for it to be part of the key grid."""
    if not row:
        return False
    return sum(is_hex_word(w["text"]) for w in row) >= len(row) * SEED_RATIO


def _columns_of(block: list[list[dict]]) -> list[float] | None:
    """
    The horizontal centre of each column of the grid, or None if the block has no shape.

    Taken only from the rows that hold the *modal* number of groups. A row where Tesseract
    broke one group in two ("bb6f" -> "bbb", "f") has a group too many and column centres
    that are all shifted, so letting it vote on the shape corrupts the shape it is about to
    be measured against.
    """
    counts = Counter(len(row) for row in block)
    modal, _ = counts.most_common(1)[0]
    typical = [row for row in block if len(row) == modal]
    return [sorted(row[i]["left"] + row[i]["width"] / 2 for row in typical)[len(typical) // 2] for i in range(modal)] or None


def _snap(row: list[dict], columns: list[float]) -> list[dict] | None:
    """
    Fits a row onto the grid's columns, merging groups that were split, or None if it will not fit.

    Once the columns are known, a row does not have to have been segmented correctly to be
    usable: each word goes to the column it sits nearest, and a column that collected more
    than one word gets a box spanning them. A column that collected nothing means this row is
    not that grid, which is what keeps a line of prose from being snapped into one.
    """
    buckets: list[list[dict]] = [[] for _ in columns]
    for word in row:
        centre = word["left"] + word["width"] / 2
        buckets[min(range(len(columns)), key=lambda i: abs(columns[i] - centre))].append(word)
    if not all(buckets):
        return None
    return [_merge(bucket) for bucket in buckets]


def candidate_runs(rows: list[list[dict]]) -> list[list[dict]]:
    """
    Finds the blocks of rows that could be the key grid, best first.

    A row *seeds* a block when most of its words read as hex, which is what keeps the status
    bar out: "18:46:08" holds a colon, and "Backed up at 08:15:42 on a cafe network" has only
    "a" and "cafe" going for it, so neither row comes close. It is a majority and not a
    unanimity because the group that reads worst is not excluded from the grid by reading
    worst -- on the fixture screenshot "353f" comes back as "SBENT", which no amount of
    hex-testing will accept, and its three neighbours have to carry it.

    A block then grows through its neighbours by **geometry rather than text**, taking any
    adjacent row that fits the same columns and is at least half hex.

    A block is usable only if its number of groups divides 64, since that is what gives pass 2
    the expected length of each group. Blocks come back longest-first: more groups means a
    shorter expected length per group, and so a tighter oracle. Each block is also offered
    row-at-a-time, as a fallback for a grid whose columns were never found.
    """
    candidates = []
    for seed_lo, seed_hi in _seed_blocks(rows):
        columns = _columns_of(rows[seed_lo:seed_hi])
        if columns is None:
            continue
        lo, hi = _grow(rows, seed_lo, seed_hi, columns)
        candidates.extend(_offers(rows[lo:hi], columns))
    return _deduplicated(candidates)


def _seed_blocks(rows: list[list[dict]]) -> list[tuple[int, int]]:
    """The maximal runs of consecutive rows that read mostly as hex."""
    seeded = [_seeds(row) for row in rows] + [False]
    blocks, start = [], None
    for i, ok in enumerate(seeded):
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            blocks.append((start, i))
            start = None
    return blocks


def _grow(rows, lo: int, hi: int, columns) -> tuple[int, int]:
    """Extends a block through neighbouring rows that fit the same columns."""
    while lo > 0 and _half_hex(rows[lo - 1]) and _snap(rows[lo - 1], columns):
        lo -= 1
    while hi < len(rows) and _half_hex(rows[hi]) and _snap(rows[hi], columns):
        hi += 1
    return lo, hi


def _offers(block: list[list[dict]], columns) -> list[list[dict]]:
    """
    Every set of boxes this block could be read as: whole first, then rows dropped off the ends.

    Dropping rows matters because a block can have grown through a row that merely looks like
    part of the grid. Each sub-block is offered both group-at-a-time and row-at-a-time.
    """
    offers: list[list[dict]] = []
    for top in range(len(block)):
        for bottom in range(len(block), top, -1):
            fitted = [_snap(row, columns) for row in block[top:bottom]]
            if any(rows is None for rows in fitted):
                continue
            snapped = [rows for rows in fitted if rows is not None]
            for groups in ([w for row in snapped for w in row], [_merge(row) for row in snapped]):
                if KEY_LENGTH % len(groups) == 0 and _granularity_agrees(groups):
                    offers.append(groups)
    return offers


def _deduplicated(candidates: list[list[dict]]) -> list[list[dict]]:
    """
    The candidates by descending group count, each set of boxes listed once.

    Dropping rows off the ends of a block regularly arrives back at boxes already listed -- a
    four-row block read row-at-a-time and its three-row sub-block read group-at-a-time can be
    the same four boxes. Every duplicate would cost another six OCR calls.
    """
    unique, seen = [], set()
    for groups in sorted(candidates, key=len, reverse=True):
        where = tuple((g["left"], g["top"], g["width"], g["height"]) for g in groups)
        if where not in seen:
            seen.add(where)
            unique.append(groups)
    return unique


def _half_hex(row: list[dict]) -> bool:
    """True if at least half a row reads as hex -- the bar for growing a block into it."""
    return bool(row) and sum(is_hex_word(w["text"]) for w in row) * 2 >= len(row)


def _granularity_agrees(groups: list[dict]) -> bool:
    """
    True if pass 1 saw groups about as long as splitting 64 between them implies.

    Four rows of four groups also divide 64 evenly when taken two rows at a time, which would
    have pass 2 demand eight digits from a box holding four and fail on every one of them.
    Pass 1's own lengths are wrong often enough not to be trusted individually -- so this asks
    only that most of them agree, not all.
    """
    expect = KEY_LENGTH // len(groups)
    agreeing = sum(len(normalize(g["text"])) == expect for g in groups)
    return agreeing * 2 >= len(groups)


@contextmanager
def single_threaded():
    """
    Pins Tesseract to one thread for the duration, which makes it several times faster.

    Tesseract is built against OpenMP, and on this workload -- many small images, one process
    per image -- letting it use every core costs far more in thread setup and contention than
    the parallelism returns. Measured on a four-core machine, one screenshot: 3.6s at one
    thread, 13.1s at four, and anywhere between 2s and 19s when left to decide for itself.
    The variance is the worse half of that; the wall time of a key read should not be a lottery.

    An OMP_THREAD_LIMIT the caller set already is left alone, and the variable is put back
    afterwards either way -- this is a library, and the setting is process-wide.
    """
    if "OMP_THREAD_LIMIT" in os.environ:
        yield
        return
    os.environ["OMP_THREAD_LIMIT"] = "1"
    try:
        yield
    finally:
        del os.environ["OMP_THREAD_LIMIT"]


def _compose(image, boxes, padding: int):
    """
    Stacks every crop into one image so a padding costs one OCR call instead of sixteen.

    The canvas is filled with the crops' own most common corner colour, so the reader sees
    the key on the background it was rendered on -- pasting a light-mode crop onto black (or
    a dark-mode one onto white) puts a hard edge beside the first glyph of every group.
    """
    from PIL import Image

    # Clamped: a group flush against the edge of a cropped screenshot would otherwise be
    # padded with black, which is a hard edge right beside its first glyph.
    crops = [
        image.crop(
            (
                max(b["left"] - padding, 0),
                max(b["top"] - padding, 0),
                min(b["left"] + b["width"] + padding, image.width),
                min(b["top"] + b["height"] + padding, image.height),
            )
        )
        for b in boxes
    ]
    corners = Counter(c.getpixel(xy) for c in crops for xy in ((0, 0), (c.width - 1, 0), (0, c.height - 1)))
    canvas = Image.new(
        crops[0].mode,
        (max(c.width for c in crops) + 2 * COMPOSE_GAP, sum(c.height + COMPOSE_GAP for c in crops) + COMPOSE_GAP),
        corners.most_common(1)[0][0],
    )
    y = COMPOSE_GAP
    for crop in crops:
        canvas.paste(crop, (COMPOSE_GAP, y))
        y += crop.height + COMPOSE_GAP
    return canvas


class Reading(NamedTuple):
    """One complete read of the grid, and the votes it was decided on."""

    key: str
    #: One Counter per cell, mapping each valid read of that cell to how many paddings gave
    #: it. The winners spell `key`; the losers are what `alternative_keys` guesses from.
    cells: tuple
    #: How many digits each cell holds -- 4 read group by group, 16 read row by row.
    span: int

    def confidence(self, cell: int) -> float:
        """How clear the vote for one cell was, from 0 (a tie) to 1 (unanimous)."""
        counts = self.cells[cell].most_common()
        total = sum(n for _, n in counts)
        runner_up = counts[1][1] if len(counts) > 1 else 0
        return (counts[0][1] - runner_up) / total


def read_cells(image, boxes: list[dict], expect: int) -> Reading | None:
    """
    Re-reads each box with the hex whitelist and votes, returning the Reading or None.

    Only reads of exactly `expect` hex digits get a vote; anything else is a known-bad read
    and is thrown away. A group with no valid read at any padding means the whole attempt
    failed, which is the signal to try the next candidate run rather than to return a key
    with a hole in it.

    The losing votes are kept rather than dropped. When the key turns out not to decrypt
    anything, they are the best evidence available for what the right digit was: a cell that
    went 4-2 is a far better place to start guessing than one that went 6-0.
    """
    import pytesseract

    config = "--psm 6 -c tessedit_char_whitelist=0123456789abcdef"
    exact = re.compile(rf"[0-9a-f]{{{expect}}}")
    votes: list[Counter] = [Counter() for _ in boxes]

    for padding in PADDINGS:
        with single_threaded():
            text = pytesseract.image_to_string(_compose(image, boxes, padding), config=config)
        lines = [line.strip().replace(" ", "") for line in text.splitlines() if line.strip()]
        if len(lines) != len(boxes):
            # The composed image did not read back as one line per crop, so the lines cannot
            # be matched to groups. Nothing to salvage; the other paddings still vote.
            log.debug("Padding %d read back %d lines for %d groups, skipping it", padding, len(lines), len(boxes))
            continue
        # strict: the length check above is what makes this pairing meaningful.
        for vote, line in zip(votes, lines, strict=True):
            if exact.fullmatch(line):
                vote[line] += 1

    if not all(votes):
        log.debug("No usable read for group(s) %s", [i for i, v in enumerate(votes) if not v])
        return None
    return Reading(key="".join(vote.most_common(1)[0][0] for vote in votes), cells=tuple(votes), span=expect)


def _grouped(key: str, size: int = 4) -> str:
    """The key in 4-digit groups, so it can be compared against the screen it came from."""
    return " ".join(key[i : i + size] for i in range(0, len(key), size))


def _first_pass(file: str | Path):
    """
    Opens the screenshot and reads it whole, with no whitelist: the greyscale image and boxes.

    Every way this can fail is a thing the user has to do something about -- install a
    package, install a program, hand over a different file -- so each one is turned into an
    InvalidKeyError that says which.
    """
    try:
        import pytesseract
        from PIL import Image
    # ImportError and not just ModuleNotFoundError: Pillow that is installed but cannot load
    # its own extension module raises the former, and that user needs this advice more, not
    # less, than the one who never installed anything.
    except ImportError as e:
        raise InvalidKeyError(
            "Reading a key from a screenshot needs {}, which could not be imported ({}).\n    "
            "Install it with: python -m pip install 'wa-crypt-tools[ocr]'".format(e.name or "pytesseract and Pillow", e)
        ) from e

    log.info("Reading the key from the screenshot, this takes a few seconds...")
    try:
        with Image.open(file) as opened:
            image = opened.convert("L")
        with single_threaded():
            return image, pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    # TesseractNotFoundError subclasses OSError, so it has to be caught before the general
    # "could not read the image" case or a missing binary is reported as a broken file.
    except pytesseract.TesseractNotFoundError as e:
        raise InvalidKeyError(
            "The tesseract program is not installed, or is not on the PATH.\n    "
            "Debian/Ubuntu: sudo apt install tesseract-ocr\n    "
            "macOS:         brew install tesseract\n    "
            "Windows:       winget install UB-Mannheim.TesseractOCR\n    "
            "Then make sure the tesseract binary is on your PATH."
        ) from e
    except OSError as e:
        raise InvalidKeyError(f"Could not read the image {file}: {e}") from e


@lru_cache(maxsize=4)
def _read(file: str) -> tuple:
    """
    Every reading of one screenshot, best first. Cached, because OCR costs ~20 seconds.

    The cache is what lets `alternative_keys` be asked for guesses *after* the key it
    returned has already turned out not to decrypt anything, without reading the image a
    second time. A CLI run reads one or two screenshots, so four entries is plenty.
    """
    image, data = _first_pass(file)
    candidates = candidate_runs(rows_from_boxes(data))
    if not candidates:
        raise InvalidKeyError(
            f"No block of hex digits was found in {file}.\n    "
            "It should be a screenshot of WhatsApp's encryption key screen, showing the "
            "64-digit key.\n    "
            "Cropping it to just the key, or using the original screenshot rather than a "
            "photo of a screen, usually fixes this."
        )

    # Read the grid at two granularities. Group by group and row by row are close to
    # independent readings -- a group read alone and the same digits read as part of a longer
    # line fail differently -- so their agreement is the only check there is on a misread that
    # happens to come out the right length. On the fixture screenshots the two agree; on a
    # rendering Tesseract finds marginal they do not, and that is when the user needs telling.
    readings: list[Reading] = []
    for groups in candidates:
        if any(len(groups) == len(reading.cells) for reading in readings):
            continue
        reading = read_cells(image, groups, KEY_LENGTH // len(groups))
        if reading is not None:
            readings.append(reading)
            if len(readings) == 2:
                break

    if not readings:
        raise InvalidKeyError(
            f"Found a block of {len(candidates[0])} hex group(s) in {file}, but could not read all of them.\n    "
            "The screenshot may be too small, blurred, or scaled down. Try the original "
            "screenshot,\n    or pass the 64 digits directly as the key argument."
        )
    return tuple(readings)


def key_from_image(file: Path) -> str:
    """
    Reads the 64-digit key off a screenshot of WhatsApp's encryption key screen.

    Raises InvalidKeyError, with what was actually seen, if no key can be read: that is a
    crop or image-quality problem, and saying so is the difference between a user recropping
    the screenshot and a user concluding their key is wrong.
    """
    readings = _read(str(file))
    key = readings[0].key
    # Debug, not info. Reading a key off a screenshot is a means to an end, and the tool that
    # has a backup to check it against (wadecrypt) repairs a misread digit without anyone
    # needing to see this. Announcing a key here that is then quietly corrected would be
    # worse than saying nothing; `wainfo -k` prints the key itself, which is its whole job.
    log.debug("Key read from the screenshot: %s", _grouped(key))
    for other in readings[1:]:
        if other.key != key:
            log.debug(
                "Reading it row by row instead gave %s -- at least one digit is a "
                "guess, and only trying them against a backup can say which.",
                _grouped(other.key),
            )
    return key


def _cell_of(reading: Reading, position: int) -> int:
    return position // reading.span


def _positions_by_doubt(reading: Reading) -> list[int]:
    """
    Every position in the key, least confidently read first.

    A cell whose vote went 4-2 is a far better place to start guessing than one that went
    6-0, and this is the only ordering available that is based on evidence about this image
    rather than on a table of what usually gets confused with what.
    """
    return sorted(range(len(reading.key)), key=lambda p: (reading.confidence(_cell_of(reading, p)), p))


def _tier_votes(readings) -> Iterator[dict]:
    """
    The losing votes. A cell that read "8c4e" four times and "8cde" twice already said what
    the second-best answer was, and that is evidence about this image rather than a table of
    what usually gets confused with what. Closest votes first.
    """
    losers: list[tuple[float, dict]] = []
    for reading in readings:
        for cell, votes in enumerate(reading.cells):
            winner, top = votes.most_common(1)[0]
            start = cell * reading.span
            losers.extend(
                (count / top, dict(zip(range(start, start + reading.span), text, strict=True)))
                for text, count in votes.items()
                if text != winner
            )
    for _, changes in sorted(losers, key=lambda pair: -pair[0]):
        yield changes


def _tier_other_reading(best: Reading, others) -> Iterator[dict]:
    """Where reading row-by-row disagreed with group-by-group, either could be right."""
    for other in others:
        yield {p: d for p, d in enumerate(other.key) if d != best.key[p]}
        for position, (mine, theirs) in enumerate(zip(best.key, other.key, strict=True)):
            if mine != theirs:
                yield {position: theirs}


def alternative_keys(file: Path, limit: int = GUESS_LIMIT) -> Iterator[str]:
    """
    Guesses at what the key on this screenshot was, best first.

    The generic machinery is `nearby.near_misses`; what this adds is the evidence pass 2
    collected and threw nothing away from. The losing votes come first because they are
    about *this* image, then the other granularity's disagreements, then every single-digit
    change and pairs of lookalikes -- both ordered least-confidently-read first, which is
    again evidence rather than a table.

    Transpositions are deliberately not offered. They are what a person copying digits does
    (see `nearby.typo_keys`); OCR reads each group where it finds it and does not reorder.
    """
    readings = _read(str(file))
    best, others = readings[0], readings[1:]
    doubted = _positions_by_doubt(best)
    return near_misses(
        best.key,
        (
            _tier_votes(readings),
            _tier_other_reading(best, others),
            one_digit(best.key, doubted),
            two_digits(best.key, doubted),
        ),
        limit,
    )
