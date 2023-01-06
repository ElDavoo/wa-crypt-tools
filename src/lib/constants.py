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