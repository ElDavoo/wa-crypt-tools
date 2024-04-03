# Changelog

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