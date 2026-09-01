from __future__ import annotations

import logging
from hashlib import md5
from os import urandom

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.errors import DecryptionError, IntegrityError
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props
from wa_crypt_tools.lib.utils import encode_varint

log = logging.getLogger(__name__)


class Database15(Database):
    def __str__(self):
        return "Database15"
        # todo

    def __init__(self, *, iv: bytes | None = None, props: Props | None = None, key_type: int | None = C.DEFAULT_KEY_TYPE):
        self.file_hash = md5()
        # just store it for now
        self.props = props
        # None writes no key_type_new at all, which is what a backup from before WhatsApp
        # added the field looks like.
        self.key_type = key_type
        if iv:
            if len(iv) != 16:
                raise IntegrityError(f"IV is not 16 bytes long but is {len(iv)} bytes long")
            self.iv = iv
        else:
            self.iv = urandom(16)

    def decrypt(self, key: Key15, encrypted: bytes) -> bytes:
        """Decrypts the database using the provided key"""
        checksum = encrypted[-16:]
        authentication_tag = encrypted[-32:-16]
        encrypted_data = encrypted[:-32]
        is_multifile_backup = False

        self.file_hash.update(encrypted_data)
        self.file_hash.update(authentication_tag)

        if self.file_hash.digest() != checksum:
            # We are probably in a multifile backup, which does not have a checksum.
            is_multifile_backup = True
        else:
            log.debug(f"Checksum OK ({self.file_hash.hexdigest()}). Decrypting...")

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

    def encrypt(self, key: Key15, props: Props, decrypted: bytes) -> bytes:
        """Encrypts the database using the provided key"""
        from wa_crypt_tools.proto import C15_IV_pb2 as C15_IV

        cipher = C15_IV.C15_IV()
        cipher.encryption_iv = self.iv
        from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
        from wa_crypt_tools.proto import key_type_pb2 as key_type

        header = prefix.BackupPrefix()
        if self.prefix is not None:
            # Start from the header this database was parsed from, so that whatever WhatsApp
            # put there and this schema does not model comes along. Current backups carry a
            # field we have no name for, and losing it is the whole difference between a
            # re-encryption that works and one that reproduces the original byte for byte.
            header.CopyFrom(self.prefix)
        header.key_type_deprecated = key_type.Key_Type.E2EE_DEPRECATED
        if self.prefix is None and self.key_type is not None:
            # Only when there is no reference to reproduce: a reference's own value has already
            # been copied in above, and overwriting it would put the field into backups made
            # before it existed.
            header.key_type_new = self.key_type
        header.e2ee_key_data.CopyFrom(cipher)

        header.backup_metadata.CopyFrom(props.get_proto())
        serialized_prefix = header.SerializeToString()
        out = b""
        file_hash = md5()
        # The size prefix is a protobuf varint, not a raw byte capped at 255: what looked like
        # a separate msgstore "feature table" flag byte was always just that varint's own
        # mandatory continuation byte for sizes in [128, 255], never an independent flag.
        out += encode_varint(len(serialized_prefix))
        file_hash.update(out)
        out += serialized_prefix
        file_hash.update(serialized_prefix)
        cipher = AES.new(key.get(), AES.MODE_GCM, self.iv)
        encrypted_data, authentication_tag = cipher.encrypt_and_digest(decrypted)
        out += encrypted_data
        file_hash.update(encrypted_data)
        out += authentication_tag
        file_hash.update(authentication_tag)
        out += file_hash.digest()
        return out

    def get_iv(self) -> bytes:
        return self.iv
