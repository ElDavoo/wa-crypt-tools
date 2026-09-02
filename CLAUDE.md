# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Setup (editable install with test extras):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test,ocr]'
```

`ocr` is the optional screenshot key reader. It also needs the `tesseract` binary on `PATH`
(`apt install tesseract-ocr`, `brew install tesseract`; on NixOS `nix shell nixpkgs#tesseract`).
Without either half the screenshot tests **skip** rather than fail, so a run missing it is
quieter than CI, not redder.

Tests must be run **from the repo root** — `tests/test_*.py` open resources by relative path
(`tests/res/...`) — and with the venv's `bin` on `PATH`, because `tests/tools-invocation/`
shells out to the installed console scripts (`wacreatekey`, ...) by bare name:

```bash
source .venv/bin/activate       # or: PATH="$PWD/.venv/bin:$PATH"
python -m pytest                # full suite
python -m pytest --cov          # with coverage (as CI runs it)
python -m pytest tests/test_decrypt.py::TestDecryption::test_decryption15   # single test
```

The full suite takes around eight minutes with the `ocr` extra installed, four without:
`tests/tools-invocation/` runs the console scripts as subprocesses, `waguess` brute-forces
offsets over a 240 KB backup for each of the three formats -- plus once more for `tests/gui/`,
which exercises the same search behind the window's "try harder" checkbox -- and the screenshot
tests do about a dozen full OCR reads at roughly twenty seconds each. Without tesseract those
skip, which is the four-minute figure.

`tests/gui/test_app.py` builds a real Tk window, so it needs both `_tkinter` and a display; it
skips cleanly without either. With `_tkinter` present and no display that is eleven skips, one
per test, unless the venv was built as "Running the window on this machine" below describes;
with no `_tkinter` at all the module skips once, at its `importorskip`. CI's Ubuntu leg runs the
suite under `xvfb-run` so that neither happens there. `tests/gui/test_core.py` is unaffected
either way -- see "The GUI" below for what makes that true, because it was not always.

A run missing both optional pieces (no tesseract, no `_tkinter`) reports 17 skips: 15 for OCR
and 2 for Tk.


Without the venv on `PATH`, the 14 `tools-invocation` tests fail with
`FileNotFoundError: 'wacreatekey'` while everything else passes.

Lint and formatting (both block; ruff replaced flake8):

```bash
ruff check .           # --fix applies the mechanical ones
ruff format .          # --check --diff is what CI runs
mypy src/wa_crypt_tools # advisory: CI reports it, does not fail on it
```

The rule set lives in `[tool.ruff.lint]` in `pyproject.toml` and is selected **explicitly**
rather than left to ruff's default. Dependabot bumps ruff daily here and ruff grows its default
set between minor releases, so an implicit set means a dependency bump can turn CI red on code
nobody touched; the `ruff >= 0.16.5, < 0.17` range in the `test` extra is the other half of that
and the upper bound should stay. Generated protobuf classes are excluded via `extend-exclude`;
`proto/fix_imports.py` sits at the repo root and *is* linted.

`[tool.ruff.lint.isort]` sets `required-imports = ["from __future__ import annotations"]`, so
every linted file carries it. It was in twelve files and missing from fifteen with nothing
telling the two groups apart; requiring it is what settles that, and it is also what lets an
annotation name something imported only for typing.

Two `per-file-ignores` are deliberate and should not be "cleaned up": `E402` in
`src/wa_crypt_tools/__init__.py`, because the `NullHandler` has to be attached before the
submodules are imported, and `SIM115` plus `PTH` in `tests/`. `SIM115` because a test hands an
open handle to `DatabaseFactory` and then reads the rest itself -- a `with` block would close it
mid-assertion. `PTH` because what that rule is for is keeping path handling in the *shipped*
code consistent, which it now is; in a test, `open("tests/res/...")` against a literal fixture
path is the clearest way to say what it says, and rewriting the 89 of them would be churn
straight through the assertions.

`G` (flake8-logging-format) is selected, so log calls take lazy `%s` arguments rather than
f-strings -- the newer code already did and the older code did not. Note ruff only recognises a
logger by name: `wacreatekey`'s was called `lo`, which is why that file went years without the
rule ever having an opinion about it. It is `log` like every other module now, and a new module
should call it that.
Three `# noqa: BLE001` carry their reason at the point of use. The same suppression in
`db15.py`/`dbfactory.py` was drift rather than intent, and those imports are at the top now.

Lint runs in its own CI job, not on each of the ten matrix legs -- the answer does not depend on
the OS or the Python version. `all-green`'s `needs` lists it, so adding another such job means
adding it there too, or the branch ruleset gates on nothing.

`.git-blame-ignore-revs` holds the whole-tree `ruff format` commit. GitHub honours it
automatically; locally it is one opt-in per clone:

```bash
git config blame.ignoreRevsFile .git-blame-ignore-revs
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

`git-hooks/pre-commit` (not installed by default) runs `ruff check`, `ruff format --check` and
then `python3 -m pytest -q`. It and `.github/scripts/agent-gates.sh` deliberately call the same
bare `ruff check .` that CI does, taking the rule set from `pyproject.toml` rather than each
repeating a selection -- three copies of a `--select` list is how they drifted before.

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

`Key14.__init__` is a two-mode constructor and the modes are two methods: `_parse(keyarray)` for
a key file's payload, `_generate(...)` for everything else, with the field-length checks on one
`_sized()` helper. Keep them apart. The public shape -- `Key14(keyarray=...)`, `Key14(key=...,
serversalt=...)`, and every `get_*()` -- is what the ABC, both factories, `db12`, `db14` and
some forty tests go through, so it is not a thing to tidy. `_parse` in particular must go on
parsing every field after a check fails: the `IntegrityError` it raises carries the whole key as
`data=self`, which is what `--force` salvages, and it collects the problems so a bad key file
reports all of them in one run rather than one per attempt.

Neither this nor `Database12` is a `@dataclass`, and that is on purpose rather than for want of
trying. A dataclass generates "assign the fields"; these constructors dispatch on *which*
argument arrived -- `keyarray` means parse, `encrypted` means read a stream, nothing means
`urandom()` -- so all of it would move to `__post_init__` unchanged, with `keyarray` and
`encrypted` as phantom fields for good measure.

**Reading a key off a screenshot** (`lib/key/ocr.py`, optional extra `[ocr]`, issue #14).
`KeyFactory.new` sniffs the first 12 bytes and routes an image to `from_image`, so a
screenshot goes wherever a key file goes and no tool grew a flag -- `wagui` included, since it
hands `wadecrypt.decrypt` a keyfile path. `pytesseract` and `PIL` are imported inside the
function; without them the user gets the pip line, not an ImportError. It is always a `Key15`:
WhatsApp only ever displays the 64-digit screen for crypt15.

The hard part is not the OCR, it is telling the key apart from the prose around it, and the
design turns on two things being true of that screen: the key is lowercase hex and nothing
else, and it is a *grid* of equal-length groups totalling 64 digits. So there are two passes
with different jobs. **Pass 1** reads the whole image with no whitelist and is used only for
*geometry* -- its text is not trusted at all (on `key-screenshot-android-2.26.png` it reads
`353f` as `SBENT` and `bc0d` as `bcoOd`), but the boxes it returns for those groups are still
right, and boxes are all it is asked for. **Pass 2** re-reads just those boxes under
`tessedit_char_whitelist=0123456789abcdef`. That whitelist is safe on a crop known to hold
nothing but hex and would be actively harmful on the whole image, where it would force the
prose into plausible hex and manufacture rows that were never there.

Four things carry the accuracy, and each was needed:
- **Length is an oracle.** Every group is exactly 64/n digits, so a read of the wrong length
  is known-bad and discarded rather than used. This is what catches `8c4e` -> `8c4de`.
- **The same crop is read at six paddings and the majority wins.** Nudging a crop by a few
  pixels changes the answer on exactly the glyphs that are marginal. On the real screenshot
  *no single padding* gets all 16 groups right and the vote gets all 16.
- **Rows are snapped to the grid's columns.** Once the columns are known a row does not have
  to have been segmented correctly: `bb6f` coming back as `bbb` + `f` gives a 5-wide row and
  a 17-group block, which divides nothing, so each word is assigned to the column it sits
  nearest and merged. A row seeds a block on a 75% hex majority, not unanimity, and a block
  then grows through neighbours by geometry rather than text.
- **The grid is read at two granularities and the answers compared.** Group-at-a-time and
  row-at-a-time fail differently, so agreement is the only check on a misread that happens to
  come out the right length.

`normalize`'s confusion map (`o`->`0`, `l`->`1`, `S`->`5` ...) only ever decides *which boxes
are the key* -- no character of the returned key passes through it, since pass 2 re-reads
everything under the whitelist. That is why it can be generous with letters that are not hex
digits and must not touch ones that are: mapping `B`->`8` would turn a correctly-read `b` into
an `8` in the comparison that picks the grid out.

Two things that look like micro-optimisations and are not. All crops for one padding are
composed into a single stacked image and read in one call, because Tesseract reloads its model
per invocation -- one call per crop is ~740ms, which turns a key read into 71 seconds. And
`single_threaded()` pins `OMP_THREAD_LIMIT=1` around every call: Tesseract is built against
OpenMP and on this workload costs 3.6s at one thread, 13.1s at four, and anywhere between 2s
and 19s left to decide for itself. A read is ~12 Tesseract calls, about 20 seconds.

**A transcribed digit is repaired against the backup, and none of it is announced.** A key
reaches this program transcribed two ways -- OCR read it off a screenshot, or a person typed
it in off one -- and either way one wrong digit fails exactly like a completely wrong key.
`wadecrypt.corrected()` runs after the header is parsed and before the whole decryption is
spent: it probes 512 bytes of ciphertext with the key it has, and only if that fails walks the
guesses. `transcribed()` decides which: a screenshot gets `ocr.alternative_keys`, 64 digits on
the command line get `nearby.typo_keys`, and a **key file gets nothing** -- its digits came out
of WhatsApp's own file byte for byte, so a near miss of them is not a thing that exists.

The oracle is `key_works()` -- waguess's trick applied to keys instead of offsets: decrypt the
first two bytes, compare against `C.ZLIB_HEADERS`, confirm a hit with a real
`test_decompression`. **Nothing unverified is ever returned**, which is what makes it safe to
guess generously; a wrong guess costs 400us and cannot produce a wrong key.

It is deliberately silent. Someone who hands over a key asked for a decryption, not for a
report on how it was arrived at, so the whole search is `log.debug` -- `-v` shows it -- and
`key_from_image` logs the key it read at debug too, because announcing a key at info that is
then quietly corrected would be worse than saying nothing. The one exception is a screenshot
that could not be repaired, which raises `ScreenshotKeyError` blaming the reader and naming
the fix: transcribe the 64 digits by hand. That is a subclass of `InvalidKeyError` rather than
a message on it, because `wagui`'s `friendly()` dispatches on type and its generic advice --
"make sure you picked the key file and not the backup" -- is actively wrong here: the file
*was* a screenshot and it was the right one. A **typed** key that cannot be repaired says
nothing at all and lets the decryption fail on its own terms; there is no reader to blame, the
user can see what they typed, and the key may simply belong to another backup.

**`lib/key/nearby.py`** holds everything generic: `near_misses(key, tiers, limit)` applies
tiers of `{position: digit}` changes, dedupes, and filters its own output to `[0-9a-f]{64}` --
callers hand it straight to `bytes.fromhex`, so that contract is enforced rather than trusted.
The tiers are the caller's because what a mistake looks like depends on who made it:

- **OCR** (`ocr.alternative_keys`) leads with the *losing votes* pass 2 collected -- a cell
  that went 4-2 said what second place was, and that is evidence about this image rather than
  a table -- then the other granularity's disagreements, then `one_digit` and `two_digits`,
  both ordered least-confidently-read first. No transpositions: OCR reads each group where it
  finds it and does not reorder.
- **Typed** (`nearby.typo_keys`) has no evidence at all, so it opens with the guarantee and
  follows with the slips specific to copying a grid by hand: `transpositions` (adjacent pairs
  first), `grid_transposed` (the 4x4 read down the columns -- one guess, and transposing is
  its own inverse so it covers the mistake both ways), and `group_swaps`.

**Every single-digit mistake is guaranteed found**, by either path: `one_digit` is 64
positions by 15 digits, all of them, whatever the tables expected. The tables only decide the
order. Two digits at once are best-effort -- the full space is 64*63/2 * 15 * 15, about 450,000
guesses and three minutes.

The two budgets differ on purpose. `GUESS_LIMIT` is 20,000 (~8s) for OCR, whose mistakes
correlate -- one bad glyph shape means several bad digits. `TYPO_LIMIT` is 4,000 (~1.6s) for a
typed key, whose mistakes do not: the structural tiers come to about 3,000 and the rest is a
slice of the two-digit tier. That cut is what keeps a plainly wrong key failing in two seconds
rather than thirteen, and a wrong key is a far commoner reason for a failed decryption than
two independent slips in 64 characters. Both are time budgets in disguise -- a candidate costs
~400us, almost all of it `AES.new(MODE_GCM)` around a 16-byte IV (357us measured; the key
derivation is only 50us).

`LOOKALIKES` **must hold hex on both sides**. It was first written with the letters Tesseract
emits -- `o`, `l`, `s`, `z`, `g` -- as the *answers*, which is the input alphabet
`ocr._CONFUSIONS` maps *from*; the two-digit tier then produced strings like `e3acf17l8c4e...`
and the caller's `bytes.fromhex` blew up. `TestLookalikes` is the tripwire, and
`near_misses`'s own filter is the belt to its braces.

`_read` is `lru_cache`d because `alternative_keys` is called *after* `key_from_image` has
already returned a key that turned out not to work, and re-reading the screenshot would cost
another twenty seconds for an answer already in hand. `TestWithoutTheExtra` has to
`cache_clear()` for that reason -- an earlier test having read the fixture would otherwise mean
the import it is trying to make fail is never reached.

`tests/lib/key/test_nearby.py` needs no OCR, no backup and no tesseract: the guessing is
string work, and whether a guess is *right* is `wadecrypt.key_works`'s job, pinned separately
in `tests/test_key_recovery.py`.

`tests/lib/key/test_ocr.py` splits along the same line the code does: everything deciding which
boxes are the key is a pure function over hand-written `image_to_data` dicts and runs with no
OCR installed, and only the "this image reads back as this key" tests need tesseract (they call
`requires_ocr()` from `tests/utils/utils.py`). `TestAlternativeKeys` patches `_read` out
entirely -- what is under test is the guessing, and running OCR to reach it would add twenty
seconds for no coverage. `tests/test_key_recovery.py` pins `key_works` on its own. The
end-to-end recovery tests stage the failure from the only reproducible direction: making
Tesseract misread on demand depends on its build, but a *backup* whose real key differs from
the screenshot by a digit puts the code in exactly the same position, so `waencrypt` builds one.

The fixtures are `key-screenshot-android-2.26.png` and `-confirm-2.26.png` (a real phone, two
different screens, the same key) and `key-screenshot-synthetic{,-dark}.png`. The synthetic pair
spells the root key of `tests/res/encrypted_backup.key`, which is what makes
`wadecrypt <screenshot> msgstore.db.crypt15` an end-to-end test against `tests/res/msgstore.db`.
**They are built by `utils/make_key_screenshot.py` out of the real screenshot's own glyphs**,
cut out with `image_to_boxes` and pasted through an alpha mask into the phone's own slot
positions. Drawing them with a font was tried at length and does not work: Pillow's bundled
Aileron has a `5` Tesseract reads as `b` in isolation at every size, and Liberation and DejaVu
render all sixteen digits correctly one at a time yet still lose `a148` to `aa8` in a grid.
Reusing the real slot positions -- not a pitch or a gap of our own choosing -- is what made
both variants read cleanly at both granularities; a fixture tuned to a lucky spacing would
break on the next Tesseract release.

CI installs `tesseract-ocr` on every leg of the matrix, Ubuntu and Windows, and `.[test,ocr]`.
Without the binary these tests *skip*, so a runner that quietly loses it goes green rather than
red -- which is why the install step is not `continue-on-error`. The same install is in
`.github/actions/project-setup/`, or the agent pipeline runs a suite that says nothing about
this feature.

**Databases** (`lib/db/`) — `Database` ABC (`decrypt`/`encrypt`/`get_iv`), implemented by
`Database12`, `Database14`, `Database15`.

`Database12.__init__` splits the same way, into `_read_header` (off a stream, checked against a
key if there is one), `_from_key` (what `waencrypt` needs) and `_from_parts`. **The `md5` is
accumulated once, after them, over the five fields in header order** -- cipher version, key
version, server salt, google id, IV. That every mode produces those five in that order is what
the four hand-rolled copies of the `file_hash.update()` calls were relying on without saying so;
a mode that departs from it breaks re-encryption byte-exactness and nothing else will notice.
`_read_header` checks each field the moment it reads it, so a mismatch still names the first
field that disagrees rather than the last.

`DatabaseFactory.from_file(stream)` reads the header off an open binary stream and decides:
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
`tests/gui/test_core.py` therefore runs anywhere -- which took the lazy re-export in
`gui/__init__.py` below to actually be true; `tests/gui/test_app.py` builds a real Tk
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

**`gui/__init__.py` re-exports `main()` lazily, through a PEP 562 module `__getattr__`, and it
has to stay that way.** `app.py` imports tkinter at module level, so importing it from the
package `__init__` dragged the display half into every import of the display-free half -- which
is exactly what `core.py` was split out to avoid. The visible symptom was that
`tests/gui/test_core.py`, written to need no display, could not even be *collected* on a Python
built without `_tkinter`, and a collection error aborts the whole run rather than skipping: the
suite reported one error and nothing else. The entry point is still `wa_crypt_tools.gui:main`,
which resolves through `__getattr__` at runtime and so did not have to change.

The cost of that is paid in `packaging/`: a lazy re-export is invisible to static analysis, so
`wagui_entry.py` imports `wa_crypt_tools.gui.app` directly and the spec adds it to
`hiddenimports`. Going back through the package there would build a binary missing `app.py`
entirely -- the same failure the protobuf modules are collected by hand to avoid, and one that
only shows up when someone double-clicks the release.

`packaging/wagui.spec` builds the release binaries, and `.gitignore`'s `*.spec` (which is in
the standard Python template *because* of PyInstaller) would hide it -- hence the
`!packaging/wagui.spec` negation. The spec is onefile everywhere except macOS, where a windowed
onefile and a `.app` bundle contradict each other and PyInstaller 7 will make it an error.
`wagui --selftest` is what CI runs against each built binary: it imports the generated protobuf
modules, which `DatabaseFactory.from_file` loads lazily and a frozen build can therefore omit
without `--version` ever noticing. `hiddenimports` names `wa_crypt_tools.gui.app` for the same
reason -- see the lazy re-export above.

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
- `fail_under = 80` in `.coveragerc` makes that number load-bearing, and it lives there rather
  than as `--cov-fail-under` on CI's pytest call so a local `python -m pytest --cov` fails the
  same way CI does. **80, not 90**, because the suite reports two very different numbers: ~94%
  where a display exists (CI's Ubuntu leg under xvfb, and Windows, where Tk needs none) and
  ~83% headless, where `tests/gui/test_app.py` skips and `gui/app.py` falls from 91% to 22%.
  The floor has to clear the lower one, or `pytest --cov` over SSH fails for a reason that has
  nothing to do with the change being tested. It still catches what it is for -- the
  subprocess-coverage breakage below takes every `wa*.py` to 0% and the total to ~57%. Raising
  it means making `app.py`'s widget code reachable without a display first.
- There is a **third** number, and it is under the floor: on a Python with no `_tkinter` at all,
  `app.py` cannot be imported, sits at 0% rather than 22%, and the total is **79%** -- so
  `pytest --cov` fails there. That machine could not run the suite at all until `gui/__init__.py`
  stopped importing tkinter eagerly, so the case is newly reachable rather than newly broken.
  The floor was left at 80 deliberately: dropping it to 78 would blunt the guard for a local
  toolchain gap that "Running the window on this machine" above already says how to close.
  CI is unaffected -- it has `_tkinter` on every leg.
- mypy is wired up but advisory (`continue-on-error` in the lint job), and the config in
  `[tool.mypy]` only sets `ignore_missing_imports` (javaobj and pycryptodomex ship no types)
  and excludes the generated protobuf. Blocking on it needs an annotation pass or a baseline
  file first. What is left is mostly `attr-defined` on protobuf messages, Liskov `override`
  complaints where `Database12`/`Key14` narrow a base-class parameter, and `str-bytes-safe` on
  diagnostics that render bytes as `b'...'` intentionally.
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
