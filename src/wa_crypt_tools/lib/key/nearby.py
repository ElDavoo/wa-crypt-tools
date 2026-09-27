"""
Keys a digit or two away from one that did not work, for a caller that can tell right from wrong.

A 64-digit key gets into this program two ways, and both of them go wrong the same way: OCR
reads it off a screenshot, or a person types it in from one. Either way a single wrong digit
fails in exactly the same manner as a completely wrong key -- "the key does not match this
backup" -- and nothing in that message distinguishes "you are one character out" from "this
key belongs to another phone".

Nothing here knows which guess is right, and nothing here can. That is the point: only
something holding the backup can tell, so this yields candidates and the caller does the
deciding. Which in turn is what makes it safe to be generous -- a guess is only ever *used*
once it has decrypted something, so a wrong guess costs microseconds and never a wrong
answer. All the ordering buys is finding the right one early.

The tiers are supplied by the caller, because what a mistake looks like depends on who made
it. `ocr.py` leads with the evidence its vote collected. A typed key has no such evidence but
has its own characteristic slips -- two digits swapped round, or a 4x4 grid read down the
columns instead of across the rows -- which no amount of substituting one digit at a time
will ever reach.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import combinations

#: How many hex digits a key has. Everything here is built on this being fixed.
KEY_LENGTH = 64

#: The key as WhatsApp displays it: sixteen groups of four, four to a row.
GROUP = 4
GRID = 4

HEX_DIGITS = "0123456789abcdef"

# Which hex digits get taken for which. Observed from Tesseract on the fixtures and on the
# font-rendered images that were tried and discarded -- 4->d in "8c4e", 5->b and 5->d in
# "2ec5", 1->d in "0e1b" -- and they serve for a person copying digits off a screen too, since
# what makes two glyphs confusable is much the same either way. Note how often the answer is
# "d" or "b": those are where a marginal glyph tends to land.
#
# Hex digits only, on both sides. The letters Tesseract emits for these -- o, l, i, s, z, g --
# belong in ocr's own confusion map, which maps *into* this alphabet; a key is made of these
# sixteen and nothing else, so anything else here would be a guess that cannot be a key.
#
# This only orders the guesses. Single-digit guesses try all sixteen regardless, so a missing
# entry costs a little time and never an answer.
LOOKALIKES = {
    "0": "d8c",
    "1": "7db",
    "2": "73d",
    "3": "89b",
    "4": "dab",
    "5": "bd6",
    "6": "b58d",
    "7": "12d",
    "8": "b60d",
    "9": "083b",
    "a": "4ed",
    "b": "685d",
    "c": "e06d",
    "d": "04ab",
    "e": "ca8d",
    "f": "17d",
}

#: A cap on how many guesses `near_misses` will produce.
#:
#: This is a time budget in disguise. Checking one guess against a backup costs about 400us,
#: almost all of it building an AES-GCM cipher around a 16-byte IV, so 20,000 guesses is
#: roughly eight seconds -- spent only on a run that was going to fail anyway. It is nowhere
#: near enough for every two-digit mistake (that would be 64*63/2 * 15 * 15, about 450,000
#: guesses and three minutes); the tiers are ordered so the budget goes on the likely ones.
#: Every *single*-digit mistake is covered long before the cap, at guess 960.
GUESS_LIMIT = 20000

#: The cap for a key somebody typed, which is much lower on purpose.
#:
#: The structural tiers -- every single digit, the transpositions, the grid read the wrong
#: way round, the group swaps -- come to about 3,000 guesses and a second and a bit. What
#: follows them is the open-ended two-digit tier, and spending another twelve seconds there
#: is a bad trade for a typed key: a wrong key is a far commoner reason for a failed
#: decryption than two independent slips of the finger in 64 characters, and every one of
#: those users would wait out the search to be told what they could have been told at once.
#: OCR gets the larger budget because its mistakes correlate -- one bad glyph shape means
#: several bad digits -- where a person's do not.
TYPO_LIMIT = 4000


def swap(key: str, changes: dict[int, str]) -> str:
    """The key with `changes` -- a {position: digit} map -- applied."""
    digits = list(key)
    for position, digit in changes.items():
        digits[position] = digit
    return "".join(digits)


def one_digit(key: str, order: Iterable[int] | None = None) -> Iterator[dict]:
    """
    Every single-digit change, in `order` of position if one is given.

    64 positions by 15 other digits is 960 guesses, which is nothing against the oracle, and
    it means *any* key wrong in one digit is found -- whether or not the lookalike table saw
    it coming. The table and `order` only decide which of the 960 comes first.
    """
    for position in order if order is not None else range(len(key)):
        rest = [d for d in HEX_DIGITS if d != key[position]]
        likely = [d for d in LOOKALIKES[key[position]] if d in rest]
        for digit in likely + [d for d in rest if d not in likely]:
            yield {position: digit}


def transpositions(key: str) -> Iterator[dict]:
    """
    Two digits swapped round, adjacent pairs first.

    The characteristic slip of copying by hand, and one that substituting a digit at a time
    never reaches: a transposition is two changes at once, and the two digits involved are
    almost never in each other's lookalike sets.
    """
    for gap in range(1, len(key)):
        for i in range(len(key) - gap):
            j = i + gap
            if key[i] != key[j]:
                yield {i: key[j], j: key[i]}


def grid_transposed(key: str) -> Iterator[dict]:
    """
    The grid read down the columns instead of across the rows.

    WhatsApp lays the key out as a 4x4 block of 4-digit groups, and a block of numbers with
    no punctuation is genuinely ambiguous about which way it is meant to be read. Transposing
    it is its own inverse, so this one guess covers the mistake in both directions.
    """
    groups = [key[i : i + GROUP] for i in range(0, len(key), GROUP)]
    if len(groups) != GRID * GRID:
        return
    reordered = "".join(groups[column * GRID + row] for row in range(GRID) for column in range(GRID))
    yield {p: d for p, d in enumerate(reordered) if d != key[p]}


def group_swaps(key: str) -> Iterator[dict]:
    """Two whole groups exchanged -- the other way a grid gets copied out of order."""
    groups = [key[i : i + GROUP] for i in range(0, len(key), GROUP)]
    for a, b in combinations(range(len(groups)), 2):
        if groups[a] == groups[b]:
            continue
        changes = {}
        for offset in range(GROUP):
            changes[a * GROUP + offset] = groups[b][offset]
            changes[b * GROUP + offset] = groups[a][offset]
        yield changes


def two_digits(key: str, order: Iterable[int] | None = None) -> Iterator[dict]:
    """Two lookalike swaps at once. Best-effort: the full two-digit space is out of budget."""
    positions = list(order) if order is not None else list(range(len(key)))
    for first, second in combinations(positions, 2):
        for one in LOOKALIKES[key[first]]:
            for two in LOOKALIKES[key[second]]:
                yield {first: one, second: two}


def near_misses(key: str, tiers: Iterable[Iterator[dict]], limit: int = GUESS_LIMIT) -> Iterator[str]:
    """
    Applies each tier's changes to `key` in turn, skipping repeats, best first.

    Yields nothing but 64-digit hex strings. Callers hand what comes out straight to
    `bytes.fromhex`, so that is enforced here rather than trusted of every tier -- a bad entry
    in a table then costs one wasted guess instead of crashing the caller. It has happened.
    """
    seen, given = {key}, 0
    for tier in tiers:
        for changes in tier:
            candidate = swap(key, changes)
            if candidate in seen or len(candidate) != KEY_LENGTH:
                continue
            if any(d not in HEX_DIGITS for d in candidate):
                continue
            seen.add(candidate)
            yield candidate
            given += 1
            if given >= limit:
                return


def typo_keys(key: str, limit: int = TYPO_LIMIT) -> Iterator[str]:
    """
    Guesses for a key that was typed in rather than read off an image.

    There is no evidence to lead with here -- nobody watched the typing -- so this opens with
    the one guarantee available, every single-digit change, and follows it with the mistakes
    that are specific to copying a grid of digits by hand: a transposition, the grid read the
    wrong way round, two groups exchanged. Those come to about 3,000 guesses, a little over a
    second, before the open-ended two-digit tier starts.
    """
    return near_misses(
        key,
        (
            one_digit(key),
            # One guess, so it costs nothing to try it before the 2,000 transpositions.
            grid_transposed(key),
            transpositions(key),
            group_swaps(key),
            two_digits(key),
        ),
        limit,
    )
