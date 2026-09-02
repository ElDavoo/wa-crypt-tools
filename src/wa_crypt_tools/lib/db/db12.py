from __future__ import annotations

import logging
from hashlib import md5
from os import urandom
from re import findall

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.errors import DecryptionError, IntegrityError, InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


class Database12(Database[Key14]):
    """
    Implementation of a crypt12 database.
    """

    def __init__(
        self,
        key: Key14 | None = None,
        encrypted=None,
        cipher_version: bytes | None = None,
        key_version: bytes | None = None,
        serversalt: bytes | None = None,
        googleid: bytes | None = None,
        iv: bytes | None = None,
    ):
        """
        Builds a crypt12 header, from a file, from a key, or from the parts.

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
        if encrypted:
            self._read_header(encrypted, key)
        elif key:
            self._from_key(key, iv)
        else:
            self._from_parts(cipher_version, key_version, serversalt, googleid, iv)
        # Hashed once here, in header order, rather than field by field as each is worked out.
        # Every branch above produces the same five fields in the same order, so the digest
        # does not depend on which one ran -- which is what the four copies of these updates
        # were quietly relying on.
        for field in (self.cipher_version, self.key_version, self.serversalt, self.googleid, self.iv):
            self.file_hash.update(field)

    def _read_header(self, encrypted, key: Key14 | None):
        """
        Reads the header off the stream, checking it against `key` if there is one.

        Each field is checked as soon as it is read, so a mismatch names the first field that
        disagrees and leaves the stream where it went wrong.
        """
        self.cipher_version = encrypted.read(2)
        if key:
            if self.cipher_version != key.get_cipher_version():
                raise IntegrityError(f"Cipher version mismatch: {self.cipher_version!r} != {key.get_cipher_version()!r}")
        elif self.cipher_version != C.SUPPORTED_CIPHER_VERSION:
            # A crypt12 header has no magic of its own, so this is the only thing telling a
            # real one apart from any other file that happens to be long enough. Without it
            # DatabaseFactory's crypt12 fallback accepts arbitrary input and reports garbage.
            raise IntegrityError(
                f"Unsupported cipher version: {self.cipher_version.hex()}.\n    "
                "This does not look like a crypt12, 14 or 15 database."
            )

        self.key_version = encrypted.read(1)
        if key and self.key_version != key.get_key_version():
            raise IntegrityError(f"Key version mismatch: {self.key_version!r} != {key.get_key_version()!r}")

        self.serversalt = encrypted.read(32)
        if key and self.serversalt != key.get_serversalt():
            raise IntegrityError(f"Server salt mismatch: {self.serversalt!r} != {key.get_serversalt()!r}")

        self.googleid = encrypted.read(16)
        if key and self.googleid != key.get_googleid():
            raise IntegrityError(f"Google ID mismatch: {self.googleid!r} != {key.get_googleid()!r}")

        self.iv = encrypted.read(16)

    def _from_key(self, key: Key14, iv: bytes | None):
        """Every field but the IV comes off the key; that is what waencrypt needs."""
        self.cipher_version = key.get_cipher_version()
        self.key_version = key.get_key_version()
        self.serversalt = key.get_serversalt()
        self.googleid = key.get_googleid()
        self.iv = iv if iv else urandom(16)

    def _from_parts(
        self,
        cipher_version: bytes | None,
        key_version: bytes | None,
        serversalt: bytes | None,
        googleid: bytes | None,
        iv: bytes | None,
    ):
        """A header out of thin air: whatever was supplied, and a random or default rest."""
        if cipher_version and cipher_version != C.SUPPORTED_CIPHER_VERSION:
            raise InvalidKeyError(f"Unsupported cipher version provided: {cipher_version.hex()}")
        if key_version and key_version not in C.SUPPORTED_KEY_VERSIONS:
            raise InvalidKeyError(f"Unsupported key version provided: {key_version.hex()}")
        self.cipher_version = cipher_version or C.SUPPORTED_CIPHER_VERSION
        self.key_version = key_version or C.SUPPORTED_KEY_VERSIONS[-1]
        self.serversalt = serversalt or urandom(32)
        self.googleid = googleid or urandom(16)
        self.iv = iv or urandom(16)

    def __str__(self) -> str:
        # !r on every field: these are bytes and are meant to read as b'...', which is what an
        # unadorned f-string does with them anyway -- spelling it out is what stops mypy
        # assuming a forgotten .decode().
        return f"""cipher_version: {self.cipher_version!r}
                    key_version: {self.key_version!r}
                    serversalt: {self.serversalt!r}
                    googleid: {self.googleid!r}
                    iv: {self.iv!r}"""

    def decrypt(self, key: Key14, encrypted: bytes) -> bytes:
        """Decrypts the database using the provided key"""
        userjid = encrypted[-4:]
        # check the userjid
        crypt12_footer = str(userjid)
        jid = findall(r"(?:-|\d)(?:-|\d)(\d\d)", crypt12_footer)
        if len(jid) != 1:
            log.error("The phone number end is not 2 characters long")
        else:
            log.debug("Your phone number ends with %s", jid[0])
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
            log.debug("Checksum OK (%s). Decrypting...", self.file_hash.hexdigest())

        cipher = AES.new(key.get(), AES.MODE_GCM, self.iv)
        try:
            output_decrypted: bytes = cipher.decrypt(encrypted_data)
        except ValueError as e:
            raise DecryptionError(f"Decryption failed: {e}.\n    This probably means your backup is corrupted.") from e

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
            raise IntegrityError(
                f"Authentication tag mismatch: {e}.\n    This probably means your backup is corrupted.", data=output_decrypted
            ) from e

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
        out += f"--{jid}".encode()
        return out

    def get_iv(self) -> bytes:
        return self.iv
