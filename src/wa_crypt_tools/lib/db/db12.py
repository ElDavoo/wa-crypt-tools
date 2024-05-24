from hashlib import md5
from os import urandom
from pathlib import Path
from re import findall

from Cryptodome.Cipher import AES

import logging

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


class Database12(Database):
    """
    Implementation of a crypt12 database.
    """

    def __init__(self, key: Key14 = None, encrypted=None,
                 cipher_version: bytes = None, key_version: bytes = None, serversalt: bytes = None,
                 googleid: bytes = None, iv: bytes = None):
        """Checks if the file is a Crypt12 file.
        Returns the cipher if it is, None otherwise."""

        """
        The crypt12 file format is similar to the crypt14 file format.
        It is a "raw" header, which means it's not a protobuf message,
        nor a serialized java object.
        Structure:
        Cipher version (2 bytes)
        Key version (1 byte)
        Server salt (32 bytes)
        Google ID (16 bytes)
        IV (16 bytes)
        ( so we finally understood why the IV is at offset 51 ... )
        """
        self.file_hash = md5()
        if encrypted and key:
            self.cipher_version = encrypted.read(2)
            if self.cipher_version != key.get_cipher_version():
                log.error("Cipher version mismatch: {} != {}".format(self.cipher_version, key.get_cipher_version()))
                raise ValueError
            self.file_hash.update(self.cipher_version)

            self.key_version = encrypted.read(1)
            if self.key_version != key.get_key_version():
                log.error("Key version mismatch: {} != {}".format(self.key_version, key.get_key_version()))
                raise ValueError
            self.file_hash.update(self.key_version)

            self.serversalt = encrypted.read(32)
            if self.serversalt != key.get_serversalt():
                log.error("Server salt mismatch: {} != {}".format(self.serversalt, key.get_serversalt()))
                raise ValueError
            self.file_hash.update(self.serversalt)

            self.googleid = encrypted.read(16)
            if self.googleid != key.get_googleid():
                log.error("Google ID mismatch: {} != {}".format(self.googleid, key.get_googleid()))
            self.file_hash.update(self.googleid)

            self.iv = encrypted.read(16)
            self.file_hash.update(self.iv)
        elif encrypted:
            self.cipher_version = encrypted.read(2)
            # if test_bytes != key.get_cipher_version():
            #    quit_12()
            self.file_hash.update(self.cipher_version)

            self.key_version = encrypted.read(1)
            # if test_bytes != key.get_key_version():
            #    quit_12()
            self.file_hash.update(self.key_version)

            self.serversalt = encrypted.read(32)
            # if test_bytes != key.get_serversalt():
            #    quit_12()
            self.file_hash.update(self.serversalt)

            self.googleid = encrypted.read(16)
            # if test_bytes != key.get_googleid():
            #    quit_12()
            self.file_hash.update(self.googleid)

            self.iv = encrypted.read(16)
            self.file_hash.update(self.iv)
        elif key:
            self.cipher_version = key.get_cipher_version()
            self.file_hash.update(self.cipher_version)
            self.key_version = key.get_key_version()
            self.file_hash.update(self.key_version)
            self.serversalt = key.get_serversalt()
            self.file_hash.update(self.serversalt)
            self.googleid = key.get_googleid()
            self.file_hash.update(self.googleid)
            if iv:
                self.iv = iv
            else:
                self.iv = urandom(16)
            self.file_hash.update(self.iv)
        else:
            if cipher_version:
                if cipher_version == C.SUPPORTED_CIPHER_VERSION:
                    self.cipher_version = cipher_version
                    self.file_hash.update(self.cipher_version)
                else:
                    log.error("Unsupported cipher version provided!")
                    raise ValueError
            else:
                self.cipher_version = C.SUPPORTED_CIPHER_VERSION
                self.file_hash.update(self.cipher_version)

            if key_version:
                if key_version in C.SUPPORTED_KEY_VERSIONS:
                    self.key_version = key_version
                    self.file_hash.update(self.key_version)
                else:
                    log.error("Unsupported key version provided!")
            else:
                self.key_version = C.SUPPORTED_KEY_VERSIONS[-1]
                self.file_hash.update(self.key_version)

            if serversalt:
                self.serversalt = serversalt
            else:
                self.serversalt = urandom(32)
            self.file_hash.update(self.serversalt)

            if googleid:
                self.googleid = googleid
            else:
                self.googleid = urandom(16)
            self.file_hash.update(self.googleid)

            if iv:
                self.iv = iv
            else:
                self.iv = urandom(16)
            self.file_hash.update(self.iv)

    def __str__(self):
        return f"""cipher_version: {self.cipher_version}
                    key_version: {self.key_version}
                    serversalt: {self.serversalt}
                    googleid: {self.googleid}
                    iv: {self.iv}"""

    def decrypt(self, key: Key14, encrypted: bytes) -> bytes:
        """Decrypts the database using the provided key"""
        userjid = encrypted[-4:]
        # check the userjid
        crypt12_footer = str(userjid)
        jid = findall(r"(?:-|\d)(?:-|\d)(\d\d)", crypt12_footer)
        if len(jid) != 1:
            log.error("The phone number end is not 2 characters long")
        else:
            log.debug("Your phone number ends with {}".format(jid[0]))
        checksum = encrypted[-20:-4]
        authentication_tag = encrypted[-36:-20]
        encrypted_data = encrypted[:-36]
        is_multifile_backup = False

        self.file_hash.update(encrypted_data)
        self.file_hash.update(authentication_tag)

        if self.file_hash.digest() != checksum:
            # We are probably in a multifile backup, which does not have a checksum.
            # TODO do crypt12 multifiles actually exist?
            is_multifile_backup = True
        else:
            log.debug("Checksum OK ({}). Decrypting...".format(self.file_hash.hexdigest()))

        cipher = AES.new(key.get(), AES.MODE_GCM, self.iv)
        try:
            output_decrypted: bytes = cipher.decrypt(encrypted_data)
        except ValueError as e:
            log.fatal("Decryption failed: {}."
                      "\n    This probably means your backup is corrupted.".format(e))
            raise e

        # Verify the authentication tag
        try:
            if is_multifile_backup:
                # In multifile backups, there is no checksum.
                # This means, the last 16 bytes of the files are not the checksum,
                # despite being called "checksum", but are the authentication tag.
                # Same way, "authentication tag" is not the tag, but the last
                # 16 bytes of the encrypted file.
                output_decrypted += cipher.decrypt(authentication_tag)
                cipher.verify(checksum)
            else:
                cipher.verify(authentication_tag)
        except ValueError as e:
            log.error("Authentication tag mismatch: {}."
                      "\n    This probably means your backup is corrupted.".format(e))

        return output_decrypted

    def encrypt(self, key: Key14, props: Props, decrypted: bytes) -> bytes:
        file_hash = md5()
        out = b""
        out += self.cipher_version
        out += self.key_version
        out += self.serversalt
        out += self.googleid
        out += self.iv
        cipher = AES.new(key.get(), AES.MODE_GCM, self.iv)
        encrypted = cipher.encrypt(decrypted)
        out += encrypted
        out += cipher.digest()
        file_hash.update(out)
        out += file_hash.digest()
        jid = props.get_jid()
        if len(jid) != 2:
            log.error("The phone number end is not 2 characters long")
        out += "--{}".format(jid).encode()
        return out

    def get_iv(self) -> bytes:
        return self.iv
