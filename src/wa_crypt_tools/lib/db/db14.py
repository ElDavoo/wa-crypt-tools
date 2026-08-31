import logging
from hashlib import md5
from os import urandom

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.errors import DecryptionError, IntegrityError
from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


class Database14(Database):

    def __init__(self, *, iv: bytes = None, props: Props = None):
        # DatabaseFactory overwrites this with the hash of the header bytes it consumed;
        # a database built for encryption starts with an empty one.
        self.file_hash = md5()
        self.props = props
        if iv:
            if len(iv) != 16:
                raise IntegrityError("IV is not 16 bytes long but is {} bytes long".format(len(iv)))
            self.iv = iv
        else:
            self.iv = urandom(16)

    def encrypt(self, key: Key, props: Props, decrypted: bytes) -> bytes:
        """Encrypts the database using the provided key"""
        from wa_crypt_tools.proto import C14_cipher_pb2 as C14_cipher
        from wa_crypt_tools.proto import key_type_pb2 as key_type

        cipher = C14_cipher.C14_cipher()
        # TODO which ones take priority? Key or self values?
        cipher.backup_cipher_header = key.get_cipher_version()
        #FIXME
        cipher.key_version = "2".encode()
        cipher.server_salt = key.get_serversalt()
        cipher.google_id_salt = key.get_googleid()
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
        header.key_type_deprecated = key_type.Key_Type.WA_PROVIDED
        header.wa_provided_key_data.CopyFrom(cipher)

        header.backup_metadata.CopyFrom(props.get_proto())
        prefix = header.SerializeToString()
        out = b''
        file_hash = md5()
        out += len(prefix).to_bytes(1, byteorder='big')
        file_hash.update(out)
        # As above: what the source had wins, and the feature list decides only when there
        # was no source to copy.
        if self.feature_table if self.feature_table is not None else len(props.get_features()) > 0:
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


    def __str__(self):
        # A crypt14 header carries none of the key fields Database12 prints: they live in
        # the key file, and the only thing this class holds of its own is the IV.
        return "Database14(iv: {})".format(self.iv.hex())


    def get_iv(self) -> bytes:
        return self.iv


    def decrypt(self, key: Key14, encrypted: bytes) -> bytes:
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
