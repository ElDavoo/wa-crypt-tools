class C:
    # These constants are only used by the guessing logic.
    # zlib magic header is 78 01 (Low Compression).
    # The first two bytes of the decrypted data should be those,
    # in case of single file backup, or PK in case of multi file.
    ZLIB_HEADERS = [
        b'x\x01',
        b'PK'
    ]
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