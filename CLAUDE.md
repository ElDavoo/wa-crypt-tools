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

The full suite takes around four minutes: `tests/tools-invocation/` runs the console
scripts as subprocesses, and `waguess` brute-forces offsets over a 240 KB backup for each of the
three formats -- plus once more for `tests/gui/`, which exercises the same search behind the
window's "try harder" checkbox.

`tests/gui/test_app.py` builds a real Tk window, so it needs both `_tkinter` and a display; it
skips cleanly without either, which is why a plain run here reports eleven skips unless the venv
was built as "Running the window on this machine" below describes. CI's Ubuntu leg runs the
suite under `xvfb-run` for the same reason.


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
the script rewrites 5 lines in `backup_prefix_pb2.py` and leaves the other five files exactly as
protoc wrote them.

There is no protoc in this environment; on NixOS a throwaway flake with `pkgs.protobuf_29` gives
a matching one (`nix develop --command protoc ...`). The committed files are protoc 29.6 output
and load under the 7.36 runtime the venv has.

`protoc` and the `protobuf` runtime must be version-matched: generated code calls
`ValidateProtobufRuntimeVersion` with the generator's version, so protoc 29.6 needs protobuf
>= 5.29.6, protoc 36.0 needs >= 7.36.0. The committed files are protoc 29.6 output.

**The field names are WhatsApp's own**, read out of `com.whatsapp` 2.26.34.7 rather than guessed:
`classes6.dex` holds `BackupPrefix` as a `GeneratedMessageLite` whose `*_FIELD_NUMBER` constants
and `newMessageInfo` field-name array survived obfuscation. That is where `key_type_deprecated`,
`wa_provided_key_data`, `e2ee_key_data`, `backup_metadata`, `passkey_encryption_metadata` and
`key_type_new` come from, and it is why the "feature table" is really a set of
`<migration>_migration_finished` flags. Two things the app does that this schema now mirrors:
fields 2 and 3 are **not** a oneof -- its message schema lists them as two ordinary optional
fields -- and fields 1 and 6 share one enum, so `Key_Type` carries all five of its values.
Renaming a field cannot change the wire format, so none of this affects what is read or written;
it only stops the header being half-anonymous.

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
- The header opens with the size of a `BackupPrefix` protobuf, encoded as a protobuf varint --
  one byte under 128, more above that. What looked like a separate `0x01` byte flagging the
  msgstore feature table was never an independent thing: it is that varint's own mandatory
  continuation byte for any size in [128, 255], which is always 1, so every msgstore header seen
  before 2026 (all of them in that range) made the two look identical. A passkey-protected
  backup's header exceeds 255 bytes and exposed the difference: a single raw size byte
  misreads it, a real multi-byte varint reads it correctly. Whether the header actually carries
  feature flags is read off `backup_metadata`'s content, not off a byte in this prefix.
  `header.c15_iv.IV` non-empty → `Database15`; `header.c14_cipher.IV` non-empty → `Database14`.
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
what users actually see; `-v` switches to DEBUG. Modules use `log = logging.getLogger(__name__)`.

Version-specific behavior belongs in a `DatabaseXX`/`KeyXX` class plus a factory branch; changes
to the base classes or to `lib/utils.py` affect all three formats, so exercise crypt12, 14 and 15
when touching them (`tests/res/` has a fixture backup in each format, all decrypting to the same
`msgstore.db`). `tests/res/stickers.backup.crypt15` is the other shape a backup comes in: a
multi-file one, so its plaintext is a ZIP (`test9.zip`) rather than a zlib'd SQLite database and
it has no trailing md5, which puts the tag where the checksum would be. It was made with
`waencrypt --no-compress --iv 000102030405060708090a0b0c0d0e0f tests/res/encrypted_backup.key
tests/res/test9.zip <out>` with the last 16 bytes then dropped. Note `--no-compress`: it is a
*raw* ZIP, so it exercises the multi-file reader but not the guessing logic, which sees a real
multi-file backup as a compressed one (see below).

**The `*-2.26.*` fixtures are real backups**, off a WhatsApp 2.26.34.7 device, and are what
`tests/lib/db/test_current_format.py` runs on: `msgstore-2.26.db.crypt15` (a current msgstore),
`wa-2.26.db.crypt15` (a backup that is not a msgstore, so `backup_metadata` carries no migration
flags, and it carries `backup_encrypted_hash`), and `msgstore-increment-2.26.crypt15` (an incremental backup,
whose payload is a compressed ZIP of JSON changesets). They exist because reconstructions kept
missing what real backups do -- `key_type_new` went unnoticed in every 2.26 backup until a
byte-for-byte comparison went looking for it, and the older fixtures cannot catch its like.

Each keeps its original header byte for byte apart from what belongs to its owner, and the
payload is the real database with the schema kept and every row deleted. To rebuild them from a
device: decrypt with the real key; for a SQLite payload `DELETE FROM` every table in
`sqlite_master` then `VACUUM INTO` a new file; for the increment, rewrite each ZIP entry keeping
its name and top-level JSON keys with empty values, and empty `messages.bin`; then parse the
original header, set `jid_suffix` to `"00"`, blank `device_model`/`lid_suffix`/`display_suffix`,
replace `backup_encrypted_hash_salt`/`backup_encrypted_hash` with `bytes(range(16))` and
`bytes(range(32))` so the fields stay present at the right length, and re-encrypt with
`Database15(iv=bytes(range(16)))` carrying `prefix` = that header and `feature_table` = whether
the source had any migration flag set, under `tests/res/encrypted_backup.key` at zlib level 9.
`test_nothing_in_these_headers_is_unknown` is the tripwire: refresh a fixture from a newer
WhatsApp and it fails until the schema catches up.

**Compression level tracks WhatsApp's own and is load-bearing in two places.** WhatsApp
compressed backups at zlib level 1 when this project was written and compresses at level 9
now. Two things had been written against level 1 and broke silently when it moved:
`waencrypt`'s hardcoded level, now `-c`/`--compression-level` defaulting to 9; and
`C.ZLIB_HEADERS`, the first-two-bytes gate `waguess` applies before it will spend time on a
candidate decryption, which held only `78 01` and so rejected every current backup with
"the key does not match this backup". All four zlib headers are listed there now, one per
band of levels, so the gate no longer depends on which level WhatsApp picks. Anything that
compares the *size* of an encrypted file against a real backup is really comparing
compression levels, and a re-encryption at 9 lands within a couple of bytes of the original.
`--reference` reads the level off the reference's own zlib header, so it reproduces a backup
of any era without being told; the default only applies when there is no reference.

`waguess` is for msgstore and nothing else, by design. Its only signal that a candidate offset
decrypted correctly is `test_decompression`, which demands a SQLite or ZIP payload, so the
sticker (WebP) and settings (JSON) backups under `WhatsApp/Backups/` come back as "the key
does not match this backup" -- and files below `HEADER_SIZE` are refused as too small. Both
are intended: `wadecrypt` and `wainfo` handle every one of those files, and broadening the
check would cost the search its only defence against false offsets.

`key_type_new` (field 6) is why re-encryption had to start from the parsed header: every
crypt15 backup from 2.26 sets it to `E2EE_ENCRYPTION_KEY`. It is written by default now --
`C.DEFAULT_KEY_TYPE`, through `Database15(key_type=...)` -- but only when there is no `prefix` to
rebuild on, because a reference from before the field existed must not grow one. `key_type=None`
asks for that older shape, which is what `tests/test_encrypt.py` does to reproduce the 2022
fixtures. The rest of the defaults in `constants.py` are that same 2.26 backup's, so with the
right `--iv` and `--jid` a reference-less `waencrypt` writes the phone's exact header bytes;
`tests/test_encrypt.py` therefore has to pass `backup_version=0` explicitly, since the default
is 1 now.

`DatabaseFactory` warns about any header field the schema cannot name
(`lib/utils.py: unknown_header_fields`, which walks nested messages too). That is the tripwire
this did not have: protobuf keeps unknown fields and hands them back on serialisation, so
`key_type_new` sat in every 2.26 backup without breaking anything and without being noticed
either. Note `FieldDescriptor.label` is gone in protobuf 7 -- use `is_repeated`.

**A re-encryption is built on the parsed header, not from scratch.** `DatabaseFactory` keeps the
`BackupPrefix` it parsed on `db.prefix`; `waencrypt` hands it to the database it builds, and
`Database14/15.encrypt` start from that prefix rather than an empty one. Real backups carry an
unknown varint field 6 this schema has no name for, and protobuf preserves it across a parse
and a `CopyFrom` -- so carrying the header through keeps it, where rebuilding from `Props` alone
dropped 2 bytes and made byte-identical output impossible.

`db.feature_table` records whether the source's `backup_metadata` had any migration flag set,
but it is purely informational now -- `encrypt()` always sizes the header with a plain protobuf
varint and never writes a byte of its own for it. It used to: `Database15` wrote an extra `0x01`
whenever it believed the source was a msgstore, and `dbfactory.py` detected "msgstore-ness" by
peeking a byte that was assumed to sit right after the header's size. Both readings were wrong
in the same way. Every msgstore header this project had ever seen was 128-255 bytes, and the
varint encoding of any size in that range mandatorily ends in a continuation byte equal to 1 --
so what looked like a deliberate flag was that byte, every time, by construction, not by
survey. A passkey-protected backup's header (over 500 bytes, `client_metadata` alone can run
past 200) needs a genuine multi-byte varint, and reading its second byte as a boolean flag
truncates the header into garbage. `header_info` already computed "feature table" correctly, by
whether `backup_metadata`'s own migration-flag fields were set -- content, not a byte in the
prefix -- and `dbfactory.py`'s duplicate, byte-peeking "No feature table found" message is gone
now that the peek is gone with it.

**crypt14 has a fourth thing that must hold: the header's own `key_version`.** `C14_cipher`
carries a key version that nothing else can supply -- the key file stores the same number as a
raw byte (`b'\x02'`) while the header spells it in ASCII (`b'2'`), so neither is derivable from
the other. `Database14.encrypt` used to write a hardcoded `b'2'`, and because it built the
submessage from scratch and assigned it with `wa_provided_key_data.CopyFrom(cipher)`, that
constant overwrote the reference's value *after* the outer `CopyFrom` meant to preserve it. It
now starts the submessage from `self.prefix.wa_provided_key_data` and only falls back to
`C.DEFAULT_C14_KEY_VERSION` when there is no reference, which also keeps any unmodelled field
nested in there. Every backup off a 2.26 device says `'2'`, so this was invisible until a
header saying otherwise was built on purpose -- it re-encrypted to a file differing at byte 13
while reporting success. `key_type_deprecated` is still set unconditionally, which is correct:
a crypt14 key is WA-provided by definition.

An incremental backup (`msgstore-increment-*.crypt15`) is a third shape: its plaintext is a
ZIP of JSON changesets, but a *compressed* one, so the ZIP header only appears after
decompression. `lib/utils.py: test_decompression` checks for it both before and after for
that reason -- before catches `stickers.backup.crypt15`, after catches the real thing.

## The GUI

`src/wa_crypt_tools/gui/` is the `wagui` window, and it is split so that the half worth testing
needs no display. `core.py` holds every decision -- `describe_backup`, `suggest_output`,
`problems`, `friendly`, the queue log handler, `run_decrypt` -- and `app.py` is widget wiring.
`tests/gui/test_core.py` therefore runs anywhere; `tests/gui/test_app.py` builds a real Tk
window and skips when there is no display.

It calls `wadecrypt.decrypt(args)` in-process with a `SimpleNamespace` rather than shelling
out: a frozen binary has no `wadecrypt` on `PATH`, and that function already owns the chunked
low-memory path, the `--force` salvage and the zlib-versus-ZIP sniffing. That is why
`wadecrypt.decrypt` raises `WaCryptError` for an existing output instead of calling `exit(1)` --
a `SystemExit` through the middle of a Tk event loop is not something a GUI can act on. The CLI
is unaffected: `main()` already caught `WaCryptError`, and `log.fatal` *is* `log.critical`.

Two things the window gets right that are easy to break. The info pane shows a one-line
headline, not `header_info`'s output -- that is `wainfo`'s rendering, three lines of which say
"crypt15" before reaching a key type and a feature list, so it goes in the Messages pane and the
headline carries the format, the app version and the jid suffix. And describing is debounced, so
a timer armed by the last keystroke can land during or after the decryption it triggered:
`start()` cancels the pending job and `_show_detail` ignores a repeat of the path already shown.
Without both, the run log is replaced by the header -- which is what a screenshot of the
finished window actually showed.

`[project.gui-scripts]`, not `[project.scripts]`: that is what makes Windows build a
console-less `wagui.exe`. tkinter is stdlib, so there is no `gui` extra; the Linux
`python3-tk` gap is documented in the README instead, since no extra can install a system
package.

`packaging/wagui.spec` builds the release binaries, and `.gitignore`'s `*.spec` (which is in
the standard Python template *because* of PyInstaller) would hide it -- hence the
`!packaging/wagui.spec` negation. The spec is onefile everywhere except macOS, where a windowed
onefile and a `.app` bundle contradict each other and PyInstaller 7 will make it an error.
`wagui --selftest` is what CI runs against each built binary: it imports the generated protobuf
modules, which `DatabaseFactory.from_file` loads lazily and a frozen build can therefore omit
without `--version` ever noticing.

### Running the window on this machine

The venv's Python needs tkinter, which the system one does not have. Build an interpreter that
does and make the venv from it:

```bash
nix build --no-link --print-out-paths --impure --expr \
  '(builtins.getFlake "flake:nixpkgs").legacyPackages.${builtins.currentSystem}.python3.withPackages (ps: [ ps.tkinter ])'
<that path>/bin/python -m venv --system-site-packages .venv   # --system-site-packages carries _tkinter in
.venv/bin/python -m pip install -e '.[test]'
```

Tk renders through XWayland on `DISPLAY=:0`. For a screenshot that is the same every time, run
under Xvfb (`nixpkgs.xvfb-run`) with no window manager, so the geometry asked for is the
geometry rendered, and capture with ImageMagick's `import -window root`; that is how
`docs/wagui.png` is made. `grim` plus `hyprctl clients -j` works for a quick look at the real
session, but Hyprland tiles the window to the monitor width, and this Hyprland's `hyprctl
dispatch` takes Lua-style arguments, so the older `setfloating address:0x...` form fails.

PyInstaller cannot build here without help: nixpkgs ships tcl and tk as separate store paths,
and PyInstaller guesses Tk's data directory as `$tcl_root/../tkX.Y`, which does not exist. It
honours `TK_LIBRARY`, so pass the path `root.tk.exprstring('$tk_library')` reports. This is a
nixpkgs split only -- the CI runners' CPython builds keep the two together, so the spec must
not encode a workaround for it.

## Notes

- Protobuf generated code lives in `src/wa_crypt_tools/proto/` and is excluded from coverage
  along with `tests/` (`.coveragerc`). `source` is scoped to `src/wa_crypt_tools`, so the reported
  TOTAL is the package's own number (~94%): `lib/` sits around 97%, the `wa*.py` entry points
  between 81% and 97%, and `gui/` at 97% for `core.py` and 91% for `app.py` -- the latter only
  reaches that where a display exists, so a headless run reports it far lower.
- `tests/tools-invocation/` shells out to the console scripts, and those subprocesses are measured
  too. It takes three pieces together and breaks silently — as 0% on every `wa*.py` — if any one
  of them goes: `parallel = true` in `.coveragerc`, the root `conftest.py` exporting
  `COVERAGE_PROCESS_START` when `--cov` is on, and the `.pth` file that `coverage` (pinned
  `>= 7.16.0` in the `test` extra for it) installs into site-packages to call
  `coverage.process_startup()`. All five tools have invocation tests; what is left uncovered is
  mostly the pycryptodome/pycryptodomex import fallback in `wadecrypt.py` and `waguess.py`, which
  cannot run in an environment where the suite runs at all.
- `waencrypt` is beta, but `--reference` reproduces a real backup byte for byte -- verified
  against 13 backups off a 2.26 device, from a 239-byte `avatar-password.bkup` to a 55 MB
  msgstore, covering SQLite, ZIP, JSON and WebP payloads. Three things have to hold at once for
  that, and each was separately broken: the zlib level has to match (see above), the header
  protobuf has to keep the fields this schema does not model, and the header's own size prefix
  has to be written as the same protobuf varint a real device would write. `--multi-file` and
  `--noparse` are declared and never read.
  Its output positional -- like `wadecrypt`'s -- is deliberately a plain `str` and not an
  `argparse.FileType('wb')`: that type opens the file during parsing, so it was emptied before
  any check had run. The existence guard at the top of `encrypt()`/`decrypt()` only works while
  it stays a path, and `wadecrypt` reaches its output twice (the chunked path opens it itself),
  so both writers have to keep taking one.
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

The workflows carry `permissions: {}` at the top and grant each job only what it needs, which is
upstream's model — the approval gate must not hold the token the stage it gates does. They are
linted by CI's own `workflows` job (actionlint + zizmor). Two zizmor findings
are ignored in place with the reason at the point of use, and both should stay: the implement and
fix checkouts must persist the push token because that is what they push with, and the CI-failure
stage really is a `workflow_run`. Everything else passes as written, so a new finding is a real
one. Note that actionlint only runs shellcheck when shellcheck is on `PATH` — a local run without
it is quieter than CI. Two shellcheck-through-actionlint traps cost a red run each: a suppression
has to sit immediately above the command it applies to, because a file-level one at the top of a
`run:` block is silently ignored, and nothing may follow `# shellcheck disable=...` on its line
or the directive fails to parse. A literal backtick inside single quotes reads as an expression,
so the workflows pass one through a `tick='`'` variable.

`agent-plan.yml` opens with a `screen` job, which is local and not part of the upstream template.
Most issues filed here are the "Can't decrypt" template submitted with every placeholder line
untouched, titled with a phone number or a first name. `.github/scripts/screen_issue.py`
subtracts the issue templates from the body and measures what is left; an empty one is closed,
and a pasted `whatsapp-consumer://` pairing link is closed and locked, because it is a live
credential for the reporter's own account. Only what survives that costs a model call, and only
`spam` from that model closes anything — its `unrelated` verdict labels and stops, because on the
issues already closed here it called a genuine question about re-encrypting to crypt14
unrelated.
