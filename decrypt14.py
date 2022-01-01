#!/usr/bin/env python

from Crypto.Cipher import AES
from os.path import isfile, getsize
import argparse
import os
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
keyhead = b'\xac\xed\x00\x05\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8' \
          b'\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x00\x00\x00\x83'
# Padding: Multiple variations 00 00 01, 00 01 01, 00 01 02 ...
known_key_paddings = [
    b'\x00\x00\x01',
    b'\x00\x01\x01',
    b'\x00\x01\x02'
]
# t1 (32 bytes)
# random IV (unused) + married key (useless for us) (48 bytes)
# 16 bytes of zeroes (padding)
# key (32 bytes)
# total length = 158 bytes
keylength = 158

force = False

known_zip_headers = [
    b'x\x01'
]


def warn(string):
    print('[W] {}'.format(string))
    if not force:
        sys.exit(1)

def oscillate(n, min, max):
    """Yields numbers from n, in order n, n-1, n+1, n-2, n+2..."""
    i = n
    c = 1
    while 0 < i < max and i > min:
        yield i
        i = i - c
        c = c + 1
        yield i
        i = i + c
        c = c + 1


def parsecmdline():
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp msgstore.db.crypt14 files')
    parser.add_argument('keyfile', nargs='?', type=argparse.FileType('rb', bufsize=keylength), default="key",
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
    if len(keyfile) != keylength:
        sys.exit(
            'Invalid key file: Smaller than expected (wanted {} bytes, got {} bytes)'.format(keylength, len(keyfile)))

    # Check if the keyfile is small enough
    if kf.read(1) != b'':
        warn('Invalid key file: Expected length of {} bytes, got more'.format(keylength))

    # Check if the keyfile has the correct header
    if keyfile[:len(keyhead)] != keyhead:
        warn('Invalid key file: Invalid header (expected {}, got {})'
             .format(keyhead.hex(), keyfile[:len(keyhead)].hex()))

    # FIXME check the "married key" (whatever that is)

    # Check if the keyfile has the correct padding
    padding_found = False
    for p in known_key_paddings:
        if p == keyfile[len(keyhead):len(keyhead) + len(known_key_paddings[0])]:
            padding_found = True
            break
    if not padding_found:
        warn('Invalid key file: Invalid padding ({}), expected one of:'
             .format(keyfile[len(keyhead):len(keyhead) + len(known_key_paddings[0])].hex()))
        for p in known_key_paddings:
            print('\t{}'.format(p.hex()))

    t1 = keyfile[30:62]

    padding = keyfile[110:126]

    # Check if the padding is correct
    for byte in padding:
        if byte != 0:
            warn('Invalid key file: Padding is not padding: {}'.format(padding.hex()))
            break

    key = keyfile[126:]

    return t1, key

def find_offset(heade, iv_offset, key):
    iv = heade[iv_offset:iv_offset + 16]
    # Determine start of data
    for f in oscillate(n=191, min=iv_offset + 16, max=512):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        d = cipher.decrypt(heade[f:f + 2])
        for h in known_zip_headers:
            if d == h:
                # We need to reinitialize the cipher everytime as it has an internal status
                cipher = AES.new(key, AES.MODE_GCM, iv)
                d2 = cipher.decrypt(heade[f:])
                try:
                    zobj = zlib.decompressobj().decompress(d2)
                    if (len(zobj) < 16):
                        sys.exit("Internal error: chunk too small (this should never happen)")
                    if zobj[:15].decode('ascii') != 'SQLite format 3':
                        sys.exit("Decryption and decompression ok but not a valid SQLite database. WTF?")
                    offset = f
                    return offset
                except zlib.error as e:
                    # We want to ignore exceptions, as that means we have a false positive
                    # (e.g., the "decrypted" bytes by chance match a valid zip header)
                    pass
                break
    return -1


def decrypt14(t1, key, crypt14, of):
    # Arbitrary number (if it is too small (<310) zlib test decompression will fail)
    heade = crypt14.read(512)
    if len(heade) < 512:
        sys.exit("Error: Encrypted DB is too small")

    result = heade.find(t1)
    if result == -1:
        warn('t1 not found in crypt14 file')
    else:
        print("t1 offset: " + str(result))

    iv = heade[67:83]

    # Finding WA version is cool and is another confirmation that the file is correct
    result = re.findall(b'\d(?:\.\d{1,3}){3}', heade)
    if len(result) != 1:
        warn('WhatsApp version not found')
    else:
        print("WhatsApp version: {}".format(result[0].decode()))

    # Determine IV offset and data offset
    for iv_offset in oscillate(n=67, min=0, max=512):
        offset = find_offset(heade, iv_offset, key)
        if offset != -1:
            print("IV offset: {}".format(iv_offset))
            print("Data offset: {}".format(offset))
            break
    if offset == -1:
        sys.exit("Error: Could not find IV or data start offset")

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
    if args.force:
        global force
        force = True
    t1, key = get_t1_key(args.keyfile)
    decrypt14(t1, key, args.encrypted, args.decrypted)


if __name__ == "__main__":
    main()
