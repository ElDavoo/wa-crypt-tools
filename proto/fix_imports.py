#!/usr/bin/env python3
"""Rewrite protoc's absolute imports into package-relative ones.

protoc emits ``import foo_pb2 as foo__pb2`` for a sibling .proto, which only
resolves if the output directory happens to be on sys.path. Inside a package it
must be ``from . import foo_pb2 as foo__pb2``. This rewrites those lines and
leaves the rest of the generated file exactly as protoc wrote it.

Usage (after running protoc):

    python proto/fix_imports.py ../src/wa_crypt_tools/proto
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fix(source: str, siblings: set[str]) -> str:
    """Make top-level imports of `siblings` relative."""
    names = "|".join(sorted(map(re.escape, siblings)))
    return re.sub(
        r"^import ({})( as \w+)?$".format(names),
        lambda m: "from . import {}{}".format(m.group(1), m.group(2) or ""),
        source,
        flags=re.MULTILINE,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    out = Path(argv[1])
    generated = sorted(out.glob("*_pb2.py"))
    if not generated:
        print("no *_pb2.py files found in {}".format(out), file=sys.stderr)
        return 1

    siblings = {path.stem for path in generated}
    fixed = 0
    for path in generated:
        source = path.read_text()
        result = fix(source, siblings)
        if result != source:
            path.write_text(result)
            fixed += 1
    print("fixed imports in {} of {} files".format(fixed, len(generated)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
