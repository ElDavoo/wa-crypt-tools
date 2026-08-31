# Changelog

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