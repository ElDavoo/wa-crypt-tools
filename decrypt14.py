#!/usr/bin/env python
"""
This script decrypts WhatsApp's encrypted DB file.
"""

# This is from pycryptodome
from Crypto.Cipher import AES

import argparse
import re
import sys
import zlib
from io import DEFAULT_BUFFER_SIZE

__author__ = 'TripCode, ElDavo'
__copyright__ = 'Copyright (C) 2022'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '2.'

# Key file format:
# fixed header (27 bytes)
KEY_HEADER = b'\xac\xed\x00\x05\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8' \
             b'\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x00\x00\x00\x83'
# Padding: Multiple variations: 00 00 01, 00 01 01, 00 01 02 ...
KEY_PADDINGS = [
    b'\x00\x00\x01',
    b'\x00\x01\x01',
    b'\x00\x01\x02'
]
# t1 (32 bytes)
# random IV (unused) + married key (useless for us) (total: 48 bytes)
# 16 bytes of zeroes (padding)
# key (32 bytes)
# total length = 158 bytes
KEY_LENGTH = 158

# zlib magic header is 78 01 (Low Compression).
# The first two bytes of the decrypted data should be those.
ZIP_HEADERS = [
    b'x\x01'
]

force = False


class Log:
    """Simple logger class. Supports 4 verbosity levels."""
    def __init__(self, verbose, force):
        self.verbose = verbose
        self.force = force

    def v(self, msg):
        """Will only print messages if verbose mode is enabled."""
        if self.verbose:
            print('[V] {}'.format(msg))

    def i(self, msg):
        """Will always print messages."""
        print('[I] {}'.format(msg))

    def w(self, msg):
        """Will print message and exit, unless force is enabled."""
        print('[W] {}'.format(msg))
        if not self.force:
            sys.exit(1)

    def e(self, msg):
        """Will always print message and exit."""
        print('[E] {}'.format(msg))
        sys.exit(1)


def oscillate(n, min, max):
    """Yields n, n-1, n+1, n-2, n+2..., with constraints:
    - n is in [min, max]
    - n is never negative
    It will revert to range() if n touches min or max.
    """
    if min < 0:
        min = 0
    i = n
    c = 1
    # First phase (n, n-1, n+1...)
    while True:
        if i == max:
            break
        yield i
        i = i - c
        c = c + 1
        if i == 0 or i == min:
            break
        yield i
        i = i + c
        c = c + 1

    # Second phase (range of remaining numbers)
    # n != i/2 fixes a bug where we would yield min and max two times if n == (max-min)/2
    if i == min and n != i/2:
        yield i
        # i touched min, revert to range()
        i = i + c
        for j in range(i,max + 1):
            yield j
    if i == max and n != i/2:
        yield max
        # i touched max, revert to range()
        i = i - c
        for j in range(i,min - 1, -1):
            yield j



def parsecmdline():
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp msgstore.db.crypt14 files')
    parser.add_argument('keyfile', nargs='?', type=argparse.FileType('rb', bufsize=KEY_LENGTH), default="key",
                        help='The WhatsApp keyfile')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt14",
                        help='The encrypted crypt14 database')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db",
                        help='The decrypted database')
    parser.add_argument('-f', '--force', action='store_true', help='Skip safety checks')

    return parser.parse_args()


# This function extracts t1 and the key from the keyfile
def get_t1_key(kf):
    # Check if the keyfile is big enough
    keyfile = kf.read()
    if len(keyfile) != KEY_LENGTH:
        log.e(
            'Invalid key file: Smaller than expected (wanted {} bytes, got {} bytes)'.format(KEY_LENGTH, len(keyfile)))

    # Check if the keyfile is small enough
    if kf.read(1) != b'':
        log.w('Invalid key file: Expected length of {} bytes, got more'.format(KEY_LENGTH))

    # Check if the keyfile has the correct header
    if keyfile[:len(KEY_HEADER)] != KEY_HEADER:
        log.w('Invalid key file: Invalid header (expected {}, got {})'
             .format(KEY_HEADER.hex(), keyfile[:len(KEY_HEADER)].hex()))

    # FIXME check the "married key" (whatever that is)

    # Check if the keyfile has the correct padding
    padding_found = False
    for p in KEY_PADDINGS:
        if p == keyfile[len(KEY_HEADER):len(KEY_HEADER) + len(KEY_PADDINGS[0])]:
            padding_found = True
            break
    if not padding_found:
        log.w('Invalid key file: Invalid padding ({}), expected one of:'
             .format(keyfile[len(KEY_HEADER):len(KEY_HEADER) + len(KEY_PADDINGS[0])].hex()))
        for p in KEY_PADDINGS:
            print('\t{}'.format(p.hex()))

    t1 = keyfile[30:62]

    padding = keyfile[110:126]

    # Check if the padding is correct
    for byte in padding:
        if byte != 0:
            log.w('Invalid key file: Padding is not padding: {}'.format(padding.hex()))
            break

    key = keyfile[126:]

    return t1, key


def find_offset(heade, iv_offset, key):
    iv = heade[iv_offset:iv_offset + 16]
    # Determine start of data
    for f in oscillate(n=191, min=iv_offset + 16, max=512):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        d = cipher.decrypt(heade[f:f + 2])
        for h in ZIP_HEADERS:
            if d == h:
                # We need to reinitialize the cipher everytime as it has an internal status
                cipher = AES.new(key, AES.MODE_GCM, iv)
                d2 = cipher.decrypt(heade[f:])
                try:
                    zobj = zlib.decompressobj().decompress(d2)
                    if len(zobj) < 16:

                        log.e("Internal error: chunk too small (this should never happen)")
                    if zobj[:15].decode('ascii') != 'SQLite format 3':
                        log.e("Decryption and decompression ok but not a valid SQLite database. WTF?")
                    offset = f
                    return offset
                except zlib.error:
                    # We want to ignore exceptions, as that means we have a false positive
                    # (e.g., the "decrypted" bytes by chance match a valid zip header)
                    pass
                break
    return -1


def decrypt14(t1, key, crypt14, of):
    # Arbitrary number (if it is too small (<310) zlib test decompression will fail)
    heade = crypt14.read(512)
    if len(heade) < 512:
        log.e("Error: Encrypted DB is too small")

    result = heade.find(t1)
    if result == -1:
        log.w('t1 not found in crypt14 file')
    else:
        log.v("t1 offset: " + str(result))

    # Finding WA version is cool and is another confirmation that the file is correct
    result = re.findall(b'\d(?:\.\d{1,3}){3}', heade)
    if len(result) != 1:
        log.w('WhatsApp version not found')
    else:
        log.v("WhatsApp version: {}".format(result[0].decode()))

    # Determine IV offset and data offset
    for iv_offset in oscillate(n=67, min=0, max=512):
        offset = find_offset(heade, iv_offset, key)
        if offset != -1:
            log.v("IV offset: {}".format(iv_offset))
            log.v("Data offset: {}".format(offset))
            break
    if offset == -1:
        log.e("Could not find IV or data start offset")

    iv = heade[iv_offset:iv_offset + 16]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    crypt14.seek(offset)

    zobj = zlib.decompressobj()
    while True:

        block = crypt14.read(DEFAULT_BUFFER_SIZE)
        if not block:
            break
        of.write(zobj.decompress(cipher.decrypt(block)))
    # of.write(zlib.decompressobj().decompress((cipher.decrypt(crypt14.read()))))
    of.close()
    crypt14.close()
    print("Decryption successful")


def main():
    args = parsecmdline()
    global log
    log = Log(verbose=False, force=args.force)
    t1, key = get_t1_key(args.keyfile)
    decrypt14(t1, key, args.encrypted, args.decrypted)


if __name__ == "__main__":
    main()
