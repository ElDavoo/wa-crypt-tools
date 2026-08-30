#!/usr/bin/env python3
"""The deterministic half of the spam screen -- see the `screen` job in agent-plan.yml.

Prints one `verdict=` line for $GITHUB_OUTPUT. Everything explanatory goes to stderr so the
step's log says why without polluting the output file.

The verdicts it can reach on its own:

  credentials  the body contains a live WhatsApp pairing link or session token
  empty        the issue is an unedited copy of an issue template, or near enough nothing
  unclear      there is real text here; the model pass in the workflow decides

It never returns `spam` or `keep`. Deciding that a body which *says something* says nothing
useful is a judgement, and this file is deliberately only the part that is not one.
"""

import os
import re
import sys
from pathlib import Path

TEMPLATES = Path(".github/ISSUE_TEMPLATE")

# What a body has to have, after the template is subtracted, to be worth a model call. Low on
# purpose: the spam this exists for leaves nothing at all behind, and the cost of guessing wrong
# in this direction is one Sonnet call, while the other direction closes someone's real issue.
MIN_RESIDUE = 25

# WhatsApp's own device-pairing URL and the fields it carries. People paste these here believing
# this is WhatsApp support; the link is a working credential for their account until they unlink
# the device.
CREDENTIALS = re.compile(
    r"whatsapp-consumer://|\bauthToken=|\botpCode=|\bsessionID=[A-Za-z0-9+/_-]{16}",
    re.IGNORECASE,
)

# A markdown image embed with no URL -- what GitHub leaves behind when an upload fails or when
# someone pastes a filename. It looks like content to a length check and is not.
EMPTY_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*\)")

HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def boilerplate() -> set[str]:
    """Every line of every issue template, front matter stripped.

    Matching whole lines rather than the template as a block is what survives the common case:
    someone answers one prompt and leaves the other six untouched.
    """
    lines: set[str] = set()
    for template in sorted(TEMPLATES.glob("*.md")):
        text = template.read_text(encoding="utf-8", errors="replace")
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) == 3:
                text = parts[2]
        for line in text.splitlines():
            stripped = line.strip()
            if stripped:
                lines.add(stripped.casefold())
    return lines


def residue(body: str, skip: set[str]) -> str:
    body = HTML_COMMENT.sub("", body.replace("\r", ""))
    body = EMPTY_IMAGE.sub("", body)
    kept = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.casefold() in skip:
            continue
        kept.append(stripped)
    return " ".join(kept).strip()


def main() -> None:
    title = os.environ.get("TITLE", "")
    body = os.environ.get("BODY", "")

    if CREDENTIALS.search(f"{title}\n{body}"):
        print("verdict=credentials")
        print("a WhatsApp pairing link or session token is in the text", file=sys.stderr)
        return

    left = residue(body, boilerplate())
    print(f"{len(left)} characters left after subtracting the templates", file=sys.stderr)
    print(f"residue: {left[:200]!r}", file=sys.stderr)

    print("verdict=empty" if len(left) < MIN_RESIDUE else "verdict=unclear")


if __name__ == "__main__":
    main()
