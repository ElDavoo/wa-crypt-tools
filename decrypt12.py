#!/usr/bin/env python

""" decrypt12.py: Decrypts WhatsApp msgstore.db.crypt12 files. """
"""               Requires pycrypto and pycryptodome packages. """

__author__       =    'TripCode'
__copyright__    =    'Copyright (C) 2016'
__license__      =    'GPLv3'
__status__       =    'Production'
__version__      =    '1.0'

from Crypto.Cipher import AES
import os
import sys
import zlib

def keyfile(kf):
    global t1, key
    if os.path.isfile(kf) == False:
        quit('The specified input key file does not exist.')
    elif os.path.getsize(kf) != 158:
        quit('The specified input key file is invalid.')
    with open(kf, 'rb') as keyfile:
        keyfile.seek(30)
        t1 = keyfile.read(32)
        keyfile.seek(126)
        key = keyfile.read(32)
    return True

def decrypt12(cf, of):
    global t2, iv
    if os.path.isfile(cf) == False:
        quit('The specified input crypt12 file does not exist.')
    tf = cf+'.tmp'
    with open(cf, 'rb') as crypt12:
        crypt12.seek(3)
        t2 = crypt12.read(32)
        if t1 != t2:
            quit('Key file mismatch or crypt12 file is corrupt.')
        crypt12.seek(51)
        iv = crypt12.read(16)
        crypt12.seek(67)
        primer(tf, crypt12, 20)
    cipher = AES.new(key, AES.MODE_GCM, iv)
    sqlite = zlib.decompress(cipher.decrypt(open(tf, 'rb').read()))
    with open(of, 'wb') as msgstore:
        msgstore.write(sqlite)
        msgstore.close()
        os.remove(tf)
    return True

def primer(tf, crypt12, sb):
    with open(tf, 'wb') as header:
        header.write(crypt12.read())
        header.close()
    with open(tf, 'rb+') as footer:
        footer.seek(-sb, os.SEEK_END)
        footer.truncate()
        footer.close()

def validate(ms):
    with open(ms, 'rb') as msgstore:
        if msgstore.read(6).decode('ascii').lower() != 'sqlite':
            os.remove(ms)
            msg = 'Decryption of crypt12 file has failed.'
        else:
            msg = 'Decryption of crypt12 file was successful.'
    msgstore.close()
    quit(msg)

def main():
    if len(sys.argv) > 2 and len(sys.argv) < 5:
        if len(sys.argv) == 3:
            outfile = 'msgstore.db'
        else:
            outfile = sys.argv[3]
        if keyfile(sys.argv[1]) and decrypt12(sys.argv[2], outfile):
            validate(outfile)
    else:
        print('\nWhatsApp Crypt12 Database Decrypter '+__version__+' '+__copyright__+' by '+__author__+'\n')
        print('\tUsage: python '+str(sys.argv[0])+' key msgstore.db.crypt12 msgstore.db\n')

if __name__ == "__main__":
    main()
