# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Setup (editable install with test extras):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

Tests must be run **from the repo root** — `tests/test_*.py` open resources by relative path
(`tests/res/...`) — and with the venv's `bin` on `PATH`, because `tests/tools-invocation/`
shells out to the installed console scripts (`wacreatekey`, ...) by bare name:

```bash
source .venv/bin/activate       # or: PATH="$PWD/.venv/bin:$PATH"
python -m pytest                # full suite
python -m pytest --cov          # with coverage (as CI runs it)
python -m pytest tests/test_decrypt.py::TestDecryption::test_decryption15   # single test
```

Without the venv on `PATH`, the 14 `tools-invocation` tests fail with
`FileNotFoundError: 'wacreatekey'` while everything else passes.

Lint (CI treats only the first as blocking):

```bash
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
```

Regenerating protobuf classes (from `proto/`, needs only a `protoc` binary — see README
"Protobuf automatic fix"):

```bash
protoc --python_out=../src/wa_crypt_tools/proto --proto_path=. *.proto
python fix_imports.py ../src/wa_crypt_tools/proto
```

`fix_imports.py` rewrites protoc's absolute imports into package-relative ones; skipping it
breaks `from wa_crypt_tools.proto import ...`. It replaces protoletariat (`protol`), which was
archived upstream and pinned `protobuf<6`. Only `backup_prefix.proto` imports other protos, so
the script rewrites 4 lines in `backup_prefix_pb2.py` and leaves the other four files exactly as
protoc wrote them. The committed files predate it and are still in protol's reformatted style, so
the next regeneration will show a one-time formatting diff across all five.

`protoc` and the `protobuf` runtime must be version-matched: generated code calls
`ValidateProtobufRuntimeVersion` with the generator's version, so protoc 29.5 needs protobuf
>= 5.29.5, protoc 36.0 needs >= 7.36.0. The committed files are protoc 29.5 output.

`git-hooks/pre-commit` (not installed by default) runs `python3 -m pytest -q`.

## Architecture

The library decrypts/encrypts WhatsApp backups in three on-disk formats — crypt12, crypt14,
crypt15 — which differ in both key storage and header layout. Two orthogonal hierarchies model
this, and version dispatch happens **only** in the factories; nothing else branches on version.

**Keys** (`lib/key/`) — `Key` ABC, implemented by `Key14` and `Key15`.
`KeyFactory.new()` accepts either a path or a raw 64-char hex string. From a file, the payload
is a Java-serialized `byte[]` (parsed via javaobj), and the version is inferred **from its
length**: 131 bytes → `Key14` (cipher version, key version, server salt, google id, hashed
google id, padding, then the 32-byte key), 32 bytes → `Key15` (a bare root key). `Key15` derives
the actual cipher key from the root key via an HMAC-SHA256 loop keyed with `b'backup encryption'`
(see `lib/utils.py: encryptionloop`, mirrored in `utils/WA_HMACSHA256_Loop.java`).

**Databases** (`lib/db/`) — `Database` ABC (`decrypt`/`encrypt`/`get_iv`), implemented by
`Database12`, `Database14`, `Database15`. `DatabaseFactory.from_file(stream)` reads the header
off an open binary stream and decides:
- Byte 0 is the size of a `BackupPrefix` protobuf; an optional `0x01` at byte 1 flags the msgstore
  feature table. `header.c15_iv.IV` non-empty → `Database15`; `header.c14_cipher.IV` non-empty →
  `Database14`.
- A `DecodeError` parsing that protobuf means it is a crypt12: the stream is `seek(0)`'d and
  handed to `Database12`, which parses the fixed-offset legacy header itself.

The stream is left positioned at the start of ciphertext, so callers do
`db = DatabaseFactory.from_file(f); encrypted = f.read(); db.decrypt(key, encrypted)`.
The factory also accumulates an `md5` of the consumed header bytes into `db.file_hash` — needed
to reproduce the original file byte-for-byte on re-encryption. Payloads are AES-GCM with the
tag/HMAC checked at the end; the plaintext is usually zlib-compressed (or a ZIP for multi-file
backups), which callers decompress themselves.

**Props** (`lib/props.py`) wraps the `BackupExpiry` protobuf: app version, jid suffix, backup
version, and the numbered boolean "feature" flags (`f_5` … `f_39`). Encryption needs these, and
they cannot be inferred from a plaintext database — hence `waencrypt --reference <existing
crypt15>`, which reads them off a real backup. `DatabaseFactory` fills `Props` from the parsed
header; `lib/constants.py: C` holds the defaults used when no reference is given.

**Entry points** (`src/wa_crypt_tools/wa*.py`) are thin argparse wrappers over the factories —
one per console script in `pyproject.toml`. Each installs `lib/logformat.py: CustomFormatter` on
both the root logger and the `wa_crypt_tools.lib` logger, so library-level `log.error(...)` is
what users actually see; `-v` switches to DEBUG. Modules use `log = logging.getLogger(__name__)`
(a few older ones use `l`).

Version-specific behavior belongs in a `DatabaseXX`/`KeyXX` class plus a factory branch; changes
to the base classes or to `lib/utils.py` affect all three formats, so exercise crypt12, 14 and 15
when touching them (`tests/res/` has a fixture backup in each format, all decrypting to the same
`msgstore.db`).

## Notes

- Protobuf generated code lives in `src/wa_crypt_tools/proto/` and is excluded from coverage
  along with `tests/` (`.coveragerc`). The `.coveragerc` does not scope `source`, so the reported
  TOTAL includes stdlib files and reads far lower than the real per-module numbers.
- `waencrypt` is beta; only crypt15 with a reference file is well tested.
- CI (`.github/workflows/lint-test-coverage.yml`) runs the matrix Python 3.10–3.14 on Ubuntu and
  Windows. On Windows, file handles must be closed before deletion — `KeyFactory.from_file` opens
  the keyfile in a `with` block for exactly this reason.

## The agent pipeline

`.github/workflows/agent-*.yml` turn an issue into a merged pull request unattended: plan,
implement, review, fix against CI, squash merge. It is a copy of `ElDavoo/agent-pipeline`, whose
README is the reference for how the stages, the trust gate and the labels work. Three files here
are the project-specific parts of it — `.github/actions/project-setup/` (toolchain),
`.github/scripts/agent-gates.sh` (the checks an agent must pass before pushing) and the prompts
in `agent-plan.yml`, `agent-implement.yml` and `agent-review.yml`.

`agent-fix-ci.yml` names `"Lint, tests, coverage"` as a literal. `workflow_run.workflows` is
matched before expressions are evaluated, so renaming that workflow without editing this one
disables the whole red-CI leg silently.

The workflows are linted by CI's own `workflows` job (actionlint + zizmor). Two zizmor findings
are ignored in place with the reason at the point of use, and both should stay: the implement and
fix checkouts must persist the push token because that is what they push with, and the CI-failure
stage really is a `workflow_run`. Everything else passes as written, so a new finding is a real
one. Note that actionlint only runs shellcheck when shellcheck is on `PATH` — a local run without
it is quieter than CI.

`agent-plan.yml` opens with a `screen` job, which is local and not part of the upstream template.
Most issues filed here are the "Can't decrypt" template submitted with every placeholder line
untouched, titled with a phone number or a first name. `.github/scripts/screen_issue.py`
subtracts the issue templates from the body and measures what is left; an empty one is closed,
and a pasted `whatsapp-consumer://` pairing link is closed and locked, because it is a live
credential for the reporter's own account. Only what survives that costs a model call, and only
`spam` from that model closes anything — its `unrelated` verdict labels and stops, because on the
issues already closed here it called a genuine question about re-encrypting to crypt14
unrelated.
