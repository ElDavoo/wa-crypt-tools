import logging
from hashlib import md5
from os import urandom

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)

from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.errors import DecryptionError, IntegrityError
from wa_crypt_tools.lib.key.key15 import Key15


class Database15(Database):
    def __str__(self):
        return "Database15"
        # todo

    def __init__(self, *, iv: bytes = None, props: Props = None):
        self.file_hash = md5()
        # just store it for now
        self.props = props
        if iv:
            if len(iv) != 16:
                raise IntegrityError("IV is not 16 bytes long but is {} bytes long".format(len(iv)))
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
            log.debug("Checksum OK ({}). Decrypting...".format(self.file_hash.hexdigest()))

        cipher = AES.new(key.get(), AES.MODE_GCM, self.iv)
        try:
            output_decrypted: bytes = cipher.decrypt(encrypted_data)
        except ValueError as e:
            raise DecryptionError("Decryption failed: {}."
                                  "\n    This probably means your backup is corrupted.".format(e)) from e

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
            raise IntegrityError("Authentication tag mismatch: {}."
                                 "\n    This probably means your backup is corrupted."
                                 .format(e), data=output_decrypted) from e

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
        header.e2ee_key_data.CopyFrom(cipher)

        header.backup_metadata.CopyFrom(props.get_proto())
        prefix = header.SerializeToString()
        out = b''
        file_hash = md5()
        out += len(prefix).to_bytes(1, byteorder='big')
        file_hash.update(out)
        # Only msgstore backups carry the feature table flag. When this database came from a
        # file we know whether that one had it; otherwise keep writing it, as this has always
        # done, since a bare Database15 is only ever built for a msgstore.
        if self.feature_table is None or self.feature_table:
            out += b'\x01'
            file_hash.update(b'\x01')
        out += prefix
        file_hash.update(prefix)
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
