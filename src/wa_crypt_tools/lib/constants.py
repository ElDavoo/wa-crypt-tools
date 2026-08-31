class C:
    # These constants are only used by the guessing logic.
    # The first two bytes of the decrypted data are a zlib header for a single file backup,
    # or PK for a multi file one stored uncompressed. With CMF 0x78 -- a 32K window, which is
    # what every level uses -- the check byte leaves exactly four possible headers, one per
    # band of compression levels. WhatsApp compressed at level 1 historically and at level 9
    # now, so a list holding only 78 01 stopped recognising current backups entirely.
    ZLIB_HEADERS = [
        b'x\x01',  # levels 0-1
        b'x\x5e',  # levels 2-5
        b'x\x9c',  # level 6, zlib's default
        b'x\xda',  # levels 7-9, what WhatsApp uses now
        b'PK'
    ]
    # A zlib header names a band of levels, not one level, so reproducing a stream from its
    # header alone means picking a representative: the top of each band, which is exact for
    # the only two levels WhatsApp has ever used, 1 and 9.
    ZLIB_HEADER_LEVELS = {
        b'x\x01': 1,
        b'x\x5e': 5,
        b'x\x9c': 6,
        b'x\xda': 9,
    }
    DEFAULT_COMPRESSION_LEVEL = 9
    ZIP_HEADER = b'PK\x03\x04'
    # Size of bytes to test (number chosen arbitrarily, but values less than ~310 makes test_decompression fail)
    HEADER_SIZE = 384
    DEFAULT_DATA_OFFSET = 122
    DEFAULT_IV_OFFSET = 8

    # Encryption constants
    DEFAULT_APP_VERSION = "2.23.18.12"
    DEFAULT_JID_SUFFIX = "00"
    DEFAULT_BACKUP_VERSION = 0
    # The Props I got from a recent backup of mine
    DEFAULT_FEATURE_LIST = [5, 6, 7, 8, 9,
                            10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                            20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                            30, 31, 32, 33, 35, 36, 37, 39]
    # Old backups might not have knowledge of the new features (in 2022 backups the max is 37)
    DEFAULT_MAX_FEATURE = 39

    # Constants for crypt12/14 key and db
    SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']