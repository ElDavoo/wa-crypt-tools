#!/usr/bin/env python
"""
Renders the synthetic key-screenshot fixtures under tests/res/.

Run it from the repo root; it overwrites the fixtures in place:

    python utils/make_key_screenshot.py

It needs Pillow, Tesseract and a system font, none of which CI has to have: the PNGs are
committed, so this runs on a developer machine and never in a test.

Why it exists
-------------
The real screenshots beside these fixtures prove the reader copes with a real device. What
they cannot do is give an end-to-end test, because the key they show is not the key of
tests/res/encrypted_backup.key -- so nothing can be decrypted with them. These fixtures show
*that* key, which is what lets a test drive wadecrypt from a screenshot and compare what
comes out against tests/res/msgstore.db.

Why the digits are cut out of the real screenshot
-------------------------------------------------
Drawing them with a font instead was tried at length and does not work. Pillow's bundled
default (Aileron, what load_default gives you) is hopeless -- Tesseract reads its "5" as a
"b", in isolation, at every size tried, whitelist or no whitelist. Liberation Sans and DejaVu
Sans do render all sixteen digits correctly one at a time, and still lose "a148" to "aa8" and
"0e1b" to "0edb" once they are laid out in a grid, at any spacing or scale tried. A phone
does not rasterize text the way PIL does, and the reader is tuned for what a phone produces.

So the glyphs are the phone's own, lifted out of the real screenshot with image_to_boxes and
labelled by the key that screenshot is known to show, then pasted through an alpha mask to
spell a different key. The mask is also what makes the dark variant possible from the same
glyphs: the ink colour is chosen at paste time rather than baked into the crop.

The prose around the grid is drawn with an ordinary system font, since none of it has to
survive OCR. It is deliberately awkward: "cafe", "beef", "1" and a clock all normalize to
hex, so a reader that merely looked for hex-shaped words would take those lines for the key.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import run

import pytesseract
from PIL import Image, ImageDraw, ImageFont, ImageOps

#: The root key of tests/res/encrypted_backup.key -- what these fixtures spell out.
KEY = "6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"

#: The screenshot the glyphs are cut out of, and the key it is known to show.
SOURCE = Path("tests/res/key-screenshot-android-2.26.png")
SOURCE_KEY = "e3acf1798c4e7e0e0d24c2a498d6fe5967517526bc0db813353feebb302cb9de"
#: The key panel within it. Everything outside is prose, and would be cut up into glyphs too.
SOURCE_PANEL = (110, 720, 970, 1050)

WIDTH, HEIGHT = 1080, 1800
#: Where the grid sits on the rendered page. Only the panel moves; inside it, every digit
#: keeps the exact slot the phone gave it (see `slots`).
PANEL_ORIGIN = (70, 620)

ABOVE = [
    "Encryption key",
    "Save this key. WhatsApp does not keep a copy of it.",
    "If you lose the key and lose your phone, WhatsApp",
    "cannot recover the backup.",
]
BELOW = ["Backed up at 08:15:42 on a cafe network.", "Deleted 1 file, beef about it later."]

#: Tried in order. Pillow resolves a bare name against the system font directories.
FONTS = ("LiberationSans-Regular.ttf", "DejaVuSans.ttf", "Arial.ttf", "Helvetica.ttc")


def _fontconfig(family: str) -> str | None:
    """Asks fontconfig where a family lives, for the distributions Pillow cannot guess."""
    try:
        found = run(["fc-match", "-f", "%{file}", family], capture_output=True, text=True, check=False)
    except (OSError, ValueError):
        return None
    return found.stdout.strip() or None


def font(size: int) -> ImageFont.FreeTypeFont:
    """The first usable system font, at `size`. Only the prose is drawn with it."""
    for name in FONTS:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    # Pillow looks in a fixed set of directories, which is not where every distribution puts
    # its fonts -- on NixOS they are all under /nix/store. fontconfig knows where they are.
    for family in ("Liberation Sans", "DejaVu Sans", "Arial", "sans-serif"):
        path = _fontconfig(family)
        if path:
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    raise SystemExit("No usable font found. Debian/Ubuntu: apt install fonts-liberation")


def cut_up_source() -> tuple[dict[str, Image.Image], list[tuple[int, int]], tuple[int, int]]:
    """
    The phone's own glyphs, and the slot each one sat in.

    Tesseract is asked for character boxes rather than words, and what it *calls* each box is
    discarded -- it gets one of the 64 wrong. The boxes come back in reading order, so the key
    that screenshot is known to show is what says which digit each one is.

    The slots come back too, and they matter as much as the glyphs. Laying the digits out on
    an invented grid instead was tried, and the reader gets one group in sixteen wrong at most
    spacings -- the phone's rhythm is not a constant pitch and not a constant gap, and a
    fixture that has to be tuned to a lucky spacing is a fixture that breaks on the next
    Tesseract release. Reusing the real positions makes this image as legible as the real one,
    which is the whole point of it.
    """
    panel = Image.open(SOURCE).convert("L").crop(SOURCE_PANEL)
    found = pytesseract.image_to_boxes(panel, config="--psm 6 -c tessedit_char_whitelist=0123456789abcdef")
    boxes = [line.split() for line in found.splitlines() if line.strip()]
    if len(boxes) != len(SOURCE_KEY):
        raise SystemExit(f"Expected {len(SOURCE_KEY)} character boxes in {SOURCE}, got {len(boxes)}")

    library: dict[str, Image.Image] = {}
    slots: list[tuple[int, int]] = []
    for digit, box in zip(SOURCE_KEY, boxes, strict=True):
        # image_to_boxes measures y from the bottom of the image, PIL from the top.
        left, bottom, right, top = (int(value) for value in box[1:5])
        slots.append((left, panel.height - bottom))  # left edge, baseline
        if digit not in library:
            crop = panel.crop((left, panel.height - top, right, panel.height - bottom))
            # Ink is dark on a light panel, so inverting gives a mask opaque on the ink. The
            # autocontrast pins it to a full 0-255 range whatever the panel's brightness was,
            # which is what lets one glyph be pasted in any colour on any background.
            library[digit] = ImageOps.autocontrast(ImageOps.invert(crop))

    missing = set("0123456789abcdef") - set(library)
    if missing:
        raise SystemExit("{} shows no {}, so those digits cannot be cut out of it".format(SOURCE, "".join(sorted(missing))))
    return library, slots, panel.size


def render(path: Path, source, background, panel_colour, ink, muted) -> None:
    library, slots, (panel_width, panel_height) = source
    image = Image.new("RGB", (WIDTH, HEIGHT), background)
    draw = ImageDraw.Draw(image)
    title, body = font(50), font(32)

    draw.text((WIDTH // 2, 150), ABOVE[0], font=title, fill=ink, anchor="mm")
    y = 300
    for line in ABOVE[1:]:
        draw.text((WIDTH // 2, y), line, font=body, fill=muted, anchor="mm")
        y += 56

    origin_x, origin_y = PANEL_ORIGIN
    draw.rounded_rectangle((origin_x, origin_y, origin_x + panel_width, origin_y + panel_height), radius=32, fill=panel_colour)

    # Each digit goes in the slot the phone put the digit it replaces in: left edge on the
    # original left edge, sitting on the original baseline. Every hex digit rests on the
    # baseline and none of them descend, so that alignment is all it takes.
    for digit, (left, baseline) in zip(KEY, slots, strict=True):
        mask = library[digit]
        image.paste(ink, (origin_x + left, origin_y + baseline - mask.height), mask)

    y = origin_y + panel_height + 90
    for line in BELOW:
        draw.text((WIDTH // 2, y), line, font=body, fill=muted, anchor="mm")
        y += 56

    image.save(path)
    print(f"wrote {path}")


def main() -> None:
    source = cut_up_source()
    res = Path("tests/res")
    render(
        res / "key-screenshot-synthetic.png",
        source,
        background=(255, 255, 255),
        panel_colour=(223, 245, 226),
        ink=(11, 20, 26),
        muted=(102, 119, 128),
    )
    # Dark mode is the variant most likely to break a reader that thresholds, or that pads a
    # crop with a colour of its own choosing, and it costs one more render.
    render(
        res / "key-screenshot-synthetic-dark.png",
        source,
        background=(11, 20, 26),
        panel_colour=(25, 46, 38),
        ink=(233, 237, 239),
        muted=(141, 151, 158),
    )


if __name__ == "__main__":
    main()
