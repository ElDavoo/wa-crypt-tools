"""
Guessing at a key that is a digit or two out.

None of this needs OCR, or a backup, or anything else: the guesses are string work, and
whether one of them is *right* is somebody else's job entirely (`wadecrypt.key_works`). What
is tested here is that the guesses are well-formed, that they are ordered so the likely ones
come first, and above all that the guarantee holds -- a key wrong in exactly one digit is
always among them.

The two callers want different things and that is the point of the split: `ocr.py` leads with
the evidence its vote collected, while a typed key has none and instead has slips of its own
that no amount of substituting single digits will reach -- two digits swapped round, or the
4x4 grid copied down the columns.
"""

import pytest

from wa_crypt_tools.lib.key import nearby

KEY = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"
GROUPS = [KEY[i : i + 4] for i in range(0, 64, 4)]


def apply(tier):
    """The keys a tier of change-sets produces."""
    return [nearby.swap(KEY, changes) for changes in tier]


class TestLookalikes:
    """
    The guess table. It has to hold hex and only hex on both sides.

    This is not a hypothetical: it was first written with the letters Tesseract emits
    (o, l, s, z, g) as the *answers*, which made the two-digit tier produce strings like
    "e3acf17l8c4e..." and blew up the caller's bytes.fromhex.
    """

    def test_every_digit_has_lookalikes(self):
        assert set(nearby.LOOKALIKES) == set(nearby.HEX_DIGITS)

    @pytest.mark.parametrize("digit", list("0123456789abcdef"))
    def test_lookalikes_are_hex_and_never_the_digit_itself(self, digit):
        others = nearby.LOOKALIKES[digit]
        assert others, f"{digit} has no lookalikes"
        assert set(others) <= set(nearby.HEX_DIGITS)
        assert digit not in others


class TestOneDigit:
    def test_it_offers_every_single_digit_change(self):
        found = set(apply(nearby.one_digit(KEY)))
        assert len(found) == 64 * 15
        for position in range(64):
            for digit in nearby.HEX_DIGITS:
                if digit != KEY[position]:
                    assert KEY[:position] + digit + KEY[position + 1 :] in found

    def test_lookalikes_come_first_for_a_position(self):
        # Same 15 guesses either way; the table only decides which are tried first.
        first_four = apply(nearby.one_digit(KEY, [0]))[: len(nearby.LOOKALIKES[KEY[0]])]
        assert [k[0] for k in first_four] == list(nearby.LOOKALIKES[KEY[0]])

    def test_the_order_of_positions_is_honoured(self):
        # Asked for position 63 only, every guess differs from the key there and nowhere else.
        guesses = apply(nearby.one_digit(KEY, [63]))
        assert len(guesses) == 15
        assert all(g[:63] == KEY[:63] and g[63] != KEY[63] for g in guesses)


class TestTranspositions:
    def test_adjacent_pairs_come_first(self):
        changes = list(nearby.transpositions(KEY))
        gaps = [max(c) - min(c) for c in changes]
        assert gaps[0] == 1
        assert gaps == sorted(gaps), "wider swaps should come after adjacent ones"

    def test_a_swapped_pair_is_reachable(self):
        swapped = KEY[:10] + KEY[11] + KEY[10] + KEY[12:]
        assert swapped in apply(nearby.transpositions(KEY))

    def test_swapping_two_equal_digits_is_not_offered(self):
        # It would produce the key it started from, which is not a guess.
        assert KEY not in apply(nearby.transpositions(KEY))


class TestGridMistakes:
    def test_the_grid_read_down_the_columns(self):
        column_major = "".join(GROUPS[c * 4 + r] for r in range(4) for c in range(4))
        assert apply(nearby.grid_transposed(KEY)) == [column_major]

    def test_transposing_is_its_own_inverse(self):
        # Which is why one guess covers the mistake in both directions.
        once = apply(nearby.grid_transposed(KEY))[0]
        assert nearby.swap(once, next(nearby.grid_transposed(once))) == KEY

    def test_two_groups_exchanged(self):
        swapped = "".join([GROUPS[0], GROUPS[2], GROUPS[1], *GROUPS[3:]])
        assert swapped in apply(nearby.group_swaps(KEY))

    def test_a_key_that_is_not_a_grid_yields_no_grid_guess(self):
        assert list(nearby.grid_transposed("abcd" * 3)) == []


class TestNearMisses:
    def test_only_well_formed_hex_keys_come_out(self):
        for guess in nearby.typo_keys(KEY):
            assert len(guess) == 64
            assert set(guess) <= set(nearby.HEX_DIGITS)

    def test_the_key_itself_is_never_offered(self):
        assert KEY not in set(nearby.typo_keys(KEY))

    def test_nothing_is_offered_twice(self):
        guesses = list(nearby.typo_keys(KEY))
        assert len(guesses) == len(set(guesses))

    def test_the_limit_is_honoured(self):
        assert len(list(nearby.typo_keys(KEY, limit=7))) == 7

    def test_a_tier_that_would_produce_a_bad_key_is_filtered_out(self):
        # The contract callers rely on: they hand this straight to bytes.fromhex. A tier
        # yielding a non-hex digit costs one wasted guess, not a crash in the caller.
        bad = ({0: "z"} for _ in range(1))
        assert list(nearby.near_misses(KEY, (bad,))) == []


class TestTypoKeys:
    """Every way a person miscopies a key, and whether the guesses reach it."""

    @pytest.mark.parametrize(
        "name, wrong",
        [
            ("first digit", "0" + KEY[1:]),
            ("last digit", KEY[:63] + "0"),
            ("a digit in the middle", KEY[:31] + "0" + KEY[32:]),
            ("two adjacent digits swapped", KEY[:10] + KEY[11] + KEY[10] + KEY[12:]),
            ("two distant digits swapped", KEY[:5] + KEY[40] + KEY[6:40] + KEY[5] + KEY[41:]),
            ("two groups swapped", "".join([GROUPS[0], GROUPS[2], GROUPS[1], *GROUPS[3:]])),
            ("the grid read down the columns", "".join(GROUPS[c * 4 + r] for r in range(4) for c in range(4))),
        ],
    )
    def test_the_real_key_is_among_the_guesses(self, name, wrong):
        # Read it the way it is used: the user typed `wrong`, and the key that works is KEY.
        assert KEY in set(nearby.typo_keys(wrong)), f"{name} is not recovered"

    def test_every_single_digit_slip_is_covered_within_the_budget(self):
        # The guarantee. Everything else is best-effort; this one is not.
        guesses = set(nearby.typo_keys(KEY))
        for position in range(64):
            for digit in nearby.HEX_DIGITS:
                if digit != KEY[position]:
                    assert KEY[:position] + digit + KEY[position + 1 :] in guesses

    def test_the_structural_tiers_all_fit_well_inside_the_budget(self):
        # They come to about 3,000 of the 4,000, so the guarantees above are not one edit
        # away from falling off the end of the limit.
        structural = list(
            nearby.near_misses(
                KEY,
                (
                    nearby.one_digit(KEY),
                    nearby.grid_transposed(KEY),
                    nearby.transpositions(KEY),
                    nearby.group_swaps(KEY),
                ),
            )
        )
        assert len(structural) < nearby.TYPO_LIMIT
