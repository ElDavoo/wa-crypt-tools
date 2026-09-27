# Changelog

## Unreleased

- **A screenshot of the key can be used as the key** (issue #14). WhatsApp shows the
  64-digit key once and never again, so most people photograph it; the screenshot now goes
  in the same argument the key file goes in, with no new flag -- `wadecrypt shot.png
  msgstore.db.crypt15 msgstore.db` works, and so do `wainfo -k shot.png` and `wagui`. It is
  an optional extra: `pip install 'wa-crypt-tools[ocr]'` plus the `tesseract` binary.
  Nothing changes and nothing new is imported for anyone who does not pass an image.

  `wadecrypt` checks the key against the backup and repairs a misread digit on its own: any
  single wrong digit is always found, and likely pairs are tried for a few seconds after
  that. A candidate is only accepted once it has decrypted something, so the result is
  verified rather than guessed. None of it is announced -- it succeeds silently, `-v` shows
  the search, and only a failure interrupts, saying the reader could not manage it and to
  transcribe the digits by hand.

- **The same repair for a key given as 64 digits on the command line.** Transcribing a key by
  hand is what the message above tells you to do, and people get a digit wrong doing it. Any
  single wrong digit is found, along with the slips particular to copying a grid: two digits
  swapped, two groups swapped, or the 4x4 grid read down the columns. It costs about a second
  and says nothing; a key that is simply wrong fails as it always did, two seconds later. Key
  *files* are never second-guessed -- nobody transcribed those.

- **A graphical front end, `wagui`.** One window: pick your key (a key file, or the
  64-character key pasted in), pick the backup, press Decrypt. Choosing a backup describes it
  straight away -- format, WhatsApp version, the last two digits of the phone number -- with
  the full header that `wainfo` prints kept in the Messages pane below. The flags that a
  support thread might ask for (`--force`, `--yes`, `--no-decompress`, `--no-mem`, verbose,
  and `waguess`'s offset search) are folded away under Advanced. Encrypting, key creation and
  offset guessing stay in the command-line tools: `waencrypt`'s reference and feature-flag
  options are not something a non-technical user can judge, and putting them a click away
  would invite silently corrupt output. Asked for in
  [discussion #167](https://github.com/ElDavoo/wa-crypt-tools/discussions/167).
- **Self-contained builds on every release.** `wagui-windows-x64.exe`,
  `wagui-macos-arm64.zip` and `wagui-linux-x64` are attached to each GitHub release, built
  from the committed `packaging/wagui.spec` so a local `pyinstaller packaging/wagui.spec`
  produces the same thing. They need no Python and no installation. Each is run with
  `--selftest` before upload, which imports the generated protobuf modules -- they are loaded
  lazily inside `DatabaseFactory.from_file`, so they are exactly what a frozen build can
  silently omit.
- `wagui` is declared under `[project.gui-scripts]` rather than `[project.scripts]`, which is
  what makes Windows build a console-less `wagui.exe`. tkinter is part of the standard
  library, so there is no new dependency; some Linux distributions package it separately
  (`python3-tk`), which the downloadable build does not need.
- `wadecrypt.decrypt()` raises `WaCryptError` when the output file exists instead of calling
  `exit(1)`. The tool prints the same message and exits with the same code -- `main()` already
  caught `WaCryptError` -- but the function is now usable from something that is not a
  command-line program.


## Version 0.2.0

The library now raises instead of logging and carrying on. This is a breaking change, and
the point of it: since version 0.0.9 moved to the `logging` framework, `log.error(...)` had
replaced a custom logger whose `e()` exited the program, so every check in the library
logged its failure and then continued anyway.

- **`decrypt()` no longer returns unauthenticated plaintext.** A failed authentication tag
  now raises `IntegrityError`, which carries the plaintext in its `data` attribute for
  callers that decide to go on with it. Version 6.1 had claimed the tag was checked; it had
  stopped being enforced.
- New exception hierarchy in `wa_crypt_tools.lib.errors`, all deriving from `ValueError`:
  `WaCryptError`, `InvalidKeyError`, `HeaderError`, `DecryptionError`, `IntegrityError`.
- `KeyFactory.new`, `KeyFactory.from_file` and `DatabaseFactory.from_file` raise instead of
  returning `None`. An unusable key no longer surfaces later as an `AttributeError`.
- **`--force` works again** in `wadecrypt` and `waencrypt`: an integrity failure stops the
  program, and `--force` writes the output anyway. It had been accepted and ignored.
- The tools now exit non-zero when they fail. Scripts that only checked the exit code were
  told everything went fine.
- A 64-character non-hex key argument reported `TypeError: object of type 'NoneType' has no
  len()`; it now says the key is invalid.
- `wa_crypt_tools` exports the factories, the classes and the errors at the top level, so
  `from wa_crypt_tools import DatabaseFactory, IntegrityError` is the supported entry point.
- Files that are not backups are rejected: the crypt12 reader checks its cipher version
  again, instead of accepting any file long enough and reporting nonsense.
- Removed the duplicated crypt14/15 header parser from `Database14`/`Database15`, which was
  dead code; `DatabaseFactory` owns the one copy that runs. Their constructors no longer
  take the `key` argument they ignored.
- `waencrypt` installs its log handler on the library logger, so library messages are
  formatted like every other tool's.
- **`wadecrypt` and `waencrypt` refuse to overwrite an existing output file**, and take
  `-y`/`--yes` to do it anyway, matching `wacreatekey`. The output was an
  `argparse.FileType('wb')`, which is opened while the arguments are still being parsed:
  pointing either tool at an existing file emptied it before any check had run, and a run
  that then failed -- an unusable key, say -- left nothing behind.
- **`waguess` works on current backups again.** It gates on the first two decrypted bytes
  matching a known zlib header before spending time on a full test decryption, and that
  list held only `78 01`, the header for levels 0 and 1. WhatsApp compressed at level 1 when
  that was written and compresses at level 9 now, so every current backup was rejected
  outright and reported as "the key does not match this backup" on a key that matched. All
  four zlib headers are accepted now.
- **Incremental and multi-file backups are recognised by the guessing logic.** Their payload
  is a ZIP that WhatsApp compresses like any other, so the ZIP header only appears after
  decompression; `test_decompression` looked for it only before, and demanded a SQLite
  header after. Found against a real incremental backup, which `waguess` failed to decrypt
  in 23 seconds and now handles in under one.
- **`waencrypt` takes `-c`/`--compression-level`**, defaulting to 9. The level was hardcoded
  to 1, again matching the WhatsApp of the time; re-encrypting a real 2.26 msgstore came out
  3.5% larger than the original at level 1 and within 2 bytes of it at level 9. Level 1
  stays reachable for reproducing older backups.
- **`--reference` now supplies the compression level too**, so reproducing a backup no longer
  means remembering `-c` alongside it. The reference's zlib header names a band of levels and
  the top of that band is used, which is exact for the only two levels WhatsApp has used. An
  explicit `-c` still wins, and a reference whose payload is not zlib warns and falls back.
- **`waencrypt --reference` reproduces a backup byte for byte.** Verified against 13 real
  backups off a 2.26 device -- a 55 MB msgstore, an incremental backup, stickers, settings,
  and files as small as 239 bytes -- every one of which now comes back with the md5 it went
  in with. Three separate things had to be fixed for that:
  - The header was rebuilt from `Props` alone, which dropped the fields this schema does not
    model. Real backups carry an unknown varint field 6, so every re-encryption was 2 bytes
    short of the original no matter what else was right. `DatabaseFactory` keeps the header
    it parsed now and `encrypt()` builds on top of it, which also future-proofs against
    WhatsApp adding fields this library has never heard of.
  - `Database15` wrote the `0x01` feature-table flag unconditionally, so every backup that is
    not a msgstore -- `wa.db`, `chatsettingsbackup`, the stickers -- came out a byte longer
    than it went in. Whether the source had it is recorded and honoured.
  - The compression level, above.
- **`waencrypt --type 14 --reference` works.** It raised `AttributeError: 'Props' object has
  no attribute 'max_feature'` from `get_features()`, which `Database14.encrypt` called to
  decide whether to write the feature table flag; it reads that off the reference now. The
  underlying hole is fixed too: `Props(v_features=...)`, which is how a parsed header becomes
  props, never set `max_feature`, so `get_features()` raised on every props built that way.
  It is taken from the protobuf schema now.
- **The protobuf schema uses WhatsApp's own field names.** They were read out of the app
  (`com.whatsapp` 2.26.34.7), not guessed: `key_type` is `key_type_deprecated`, `c14_cipher` is
  `wa_provided_key_data`, `c15_iv` is `e2ee_key_data`, `info` is `backup_metadata`, and the
  `f_5`..`f_39` flags turn out to be `<migration>_migration_finished` -- the "feature table" is
  a record of which database migrations had run. Three fields this library did not model are in
  the schema now: `passkey_encryption_metadata` (5), `key_type_new` (6), and, inside
  `BackupExpiry`, `backup_encrypted_hash_salt`/`backup_encrypted_hash` (40, 41) which every
  backup that is not a msgstore carries. `Key_Type` gained the values it was missing --
  `E2EE_PASSWORD`, `E2EE_ENCRYPTION_KEY`, `E2EE_PASSKEY` -- and what this project called
  `HSM_CONTROLLED` is really `E2EE_DEPRECATED`. Renaming a field cannot change the wire format,
  so nothing about what is read or written changes.
- **The defaults are a real 2.26.34.7 backup's.** `DEFAULT_APP_VERSION` was 2.23.18.12 and
  `DEFAULT_BACKUP_VERSION` was 0; the feature list was missing flag 34. With the right `--iv`
  and `--jid`, `waencrypt` given no reference at all now writes the same header bytes as the
  phone does. `Database15` also takes a `key_type`, defaulting to `E2EE_ENCRYPTION_KEY`, which
  is what `key_type_new` holds in every current backup -- pass `None` to reproduce a backup
  from before that field existed. A `--reference` still wins over all of it.
- **A header field this schema cannot name is now reported.** `waguess`, `wadecrypt` and
  `wainfo` warn, naming the message and the field number. Unknown fields survive a parse and
  come back on re-encryption, so nothing broke while `key_type_new` went unnoticed in every
  2.26 backup -- and nothing said anything either. Now it would.
- **The test suite runs on real current backups.** Three fixtures off a WhatsApp 2.26.34.7
  device -- a msgstore, a backup that is not a msgstore, and an incremental one -- each keeping
  its original header byte for byte apart from the owner's own fields, with the payload's schema
  kept and every row deleted. The reconstructions the suite had could not have caught
  `key_type_new`, since they were built from the same schema that did not know about it.
- `wainfo` printed the crypt15 IV on the same line as the heading that introduces it, unlike
  the crypt14 branch beside it, so anything reading its output line by line missed the IV.

## Version 0.0.9

- Code refactored as a library, with lots of files, classes and methods
- decrypt14_15 renamed to wadecrypt
- Guessing logic moved to waguess
- New tools introduced:
  - wacreatekey
  - waencrypt, for encrypting backups
  - wainfo, for printing infos

## Version 0.0.8

As I uploaded the package to PyPI, the versioning scheme changed. It was too ugly to start from version 7.0.  

- Uploaded package to PyPI

## Old changelogs
---

Note: this script did not use to follow a versioning policy. Versions number were written just for reference.
This file may not be 100% correct: The true changelog is the git history.

## Version 7.0

- Support for crypt12 files (only msgstore tested)

## Version 6.1

- The AES authentication tag is now checked.  
  This is the beginning of a new era as everything is checked properly.

## Version 6.0

- The MD5 checksum at the end of the file is now checked.

## Version 5.4

- Support for key version 3

## Version 5.3

- You can now specify a custom buffer size to be used.

## Version 5.2

- You can write the hex encoded key (crypt15) directly instead of specifying the key file.

## Version 5.1

- More command line switches 
(you can choose the approach and the default offsets for guessing mode)

## Version 5.0

- Unified the crypt14 and the crypt15 code bases.

## Version 4.1

- (Crypt15) Support for other DB files, like stickers, chat_settings, wallpapers...  
Note: stickers and wallpapers are ZIP files that will not be decompressed automatically.

## Version 4.0
- (crypt15) No more guessing offsets! The database header is now completely parsed.
  The guessing logic has been left as a fallback behaviour.
  The structure of the program has been changed accordingly.
- The proto file for msgstore.db.crypt15 are now complete

## Version 3.0
- crypt15 support (in a separate script, decrypt15.py)
- added a proto file describing the header of a msgstore.db.crypt15 file

## Version 2.2
- The Java object from the "key" file is now correctly deserialized, instead of just ignoring the header.
- The SHA256 of the googleIdSalt in the "key" file is now actually checked.
- Added a utility to read "password_data.key" and give a hashcat representation of the file.
- Moved the changelog to a separate file.

## Version 2.1
- Refactoring
- Added new command line options

## Version 2.0 is here!
Since the file format keeps changing, I decided to completely reimplement the script.
It should be much more efficient, and it should handle small variations of offset **automatically**.

## Version 1.1
- Added support for crypt14, via fixed headers.

## Version 1.0
- Initial implementation by TripCode for crypt12 files.