import logging
from hashlib import md5
from os import urandom
from re import findall

from Cryptodome.Cipher import AES
from google.protobuf.message import DecodeError

from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.props import Props

l = logging.getLogger(__name__)


class Database14(Database):

    def __init__(self, key: Key14 = None, encrypted=None, file_hash=None,
                 cipher_version: bytes = None, key_version: bytes = None, serversalt: bytes = None,
                 googleid: bytes = None, iv: bytes = None,
                 props: Props = None):
        self.props = props
        if encrypted and file_hash:
            try:
                from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
                from wa_crypt_tools.proto import key_type_pb2 as key_type
            except ImportError as e:
                l.error("Could not import the proto classes: {}".format(e))
                if str(e).startswith("cannot import name 'builder' from 'google.protobuf.internal'"):
                    l.error("You need to upgrade the protobuf library to at least 3.20.0.\n"
                            "    python -m pip install --upgrade protobuf")
                elif str(e).startswith("no module named"):
                    l.error("Please download them and put them in the \"proto\" sub folder.")
                raise e
            except AttributeError as e:
                l.error("Could not import the proto classes: {}\n    ".format(e) +
                        "Your protobuf library is probably too old.\n    "
                        "Please upgrade to at least version 3.20.0 , by running:\n    "
                        "python -m pip install --upgrade protobuf")
                raise e

            self.header = prefix.BackupPrefix()

            l.debug("Parsing database header...")

            try:

                # The first byte is the size of the upcoming protobuf message
                protobuf_size = encrypted.read(1)
                file_hash.update(protobuf_size)
                protobuf_size = int.from_bytes(protobuf_size, byteorder='big')

                # A 0x01 as a second byte indicates the presence of the feature table in the protobuf.
                # It is optional and present only in msgstore database, although
                # I found some old msgstore backups without it, so it is optional.
                msgstore_features_flag = encrypted.peek(1)[0]
                if msgstore_features_flag != 1:
                    msgstore_features_flag = 0
                else:
                    file_hash.update(encrypted.read(1))
                if not msgstore_features_flag:
                    l.debug("No feature table found (not a msgstore DB or very old)")
                self.__msgstore_features_flag = msgstore_features_flag
                try:

                    protobuf_raw = encrypted.read(protobuf_size)
                    file_hash.update(protobuf_raw)

                    if self.header.ParseFromString(protobuf_raw) != protobuf_size:
                        l.error("Protobuf message not fully read. Please report a bug.")
                    else:

                        # Checking and printing WA version and phone number
                        self.__version = findall(r"\d(?:\.\d{1,3}){3}", self.header.info.app_version)
                        if len(self.__version) != 1:
                            l.error('WhatsApp version not found')
                        else:
                            l.debug("WhatsApp version: {}".format(self.__version[0]))
                        if len(self.header.info.jidSuffix) != 2:
                            l.error("The phone number end is not 2 characters long")
                        l.debug("Your phone number ends with {}".format(self.header.info.jidSuffix))

                        if len(self.header.c15_iv.IV) != 0:
                            # DB Header is crypt15
                            # if type(key) is not Key15:
                            #    l.error("You are using a crypt14 key file with a crypt15 backup.")
                            raise ValueError("Crypt15 file in crypt14 constructor!")

                        elif len(self.header.c14_cipher.IV) != 0:

                            # DB Header is crypt14
                            # if type(key) is not Key14:
                            #    l.fatal("You are using a crypt15 key file with a crypt14 backup.")

                            # if key.cipher_version != p.c14_cipher.version.cipher_version:
                            #    l.error("Cipher version mismatch: {} != {}"
                            #    .format(key.cipher_version, p.c14_cipher.cipher_version))

                            # Fix bytes to string encoding
                            # key.key_version = (key.key_version[0] + 48).to_bytes(1, byteorder='big')
                            # if key.key_version != p.c14_cipher.key_version:
                            #     if key.key_version > p.c14_cipher.key_version:
                            #         l.error("Key version mismatch: {} != {} .\n    "
                            #             .format(key.key_version, p.c14_cipher.key_version) +
                            #             "Your backup is too old for this key file.\n    " +
                            #             "Please try using a newer backup.")
                            #     elif key.key_version < p.c14_cipher.key_version:
                            #         l.error("Key version mismatch: {} != {} .\n    "
                            #             .format(key.key_version, p.c14_cipher.key_version) +
                            #             "Your backup is too new for this key file.\n    " +
                            #             "Please try using an older backup, or getting the new key.")
                            #     else:
                            #         l.error("Key version mismatch: {} != {} (?)"
                            #             .format(key.key_version, p.c14_cipher.key_version))
                            # if key.get_serversalt() != p.c14_cipher.server_salt:
                            #     l.error("Server salt mismatch: {} != {}".format(key.get_serversalt(), p.c14_cipher.server_salt))
                            # if key.get_googleid() != p.c14_cipher.google_id:
                            #     l.error("Google ID mismatch: {} != {}".format(key.get_googleid(), p.c14_cipher.google_id))
                            if len(self.header.c14_cipher.IV) != 16:
                                l.error("IV is not 16 bytes long but is {} bytes long".format(
                                    len(self.header.c14_cipher.IV)))
                            self.__iv = self.header.c14_cipher.IV

                        else:
                            l.error("Could not parse the IV from the protobuf message. Please report a bug.")
                            raise ValueError


                except DecodeError as e:

                    print(e)

            except OSError as e:
                l.fatal("Reading database header failed: {}".format(e))
        else:
            if iv:
                self.__iv = iv
            else:
                self.__iv = urandom(16)


    def encrypt(self, key: Key, props: Props, decrypted: bytes) -> bytes:
        """Encrypts the database using the provided key"""
        from wa_crypt_tools.proto import C14_cipher_pb2 as C14_cipher
        from wa_crypt_tools.proto import key_type_pb2 as key_type

        cipher = C14_cipher.C14_cipher()
        # TODO which ones take priority? Key or self values?
        cipher.cipher_version = key.get_cipher_version()
        #FIXME
        cipher.key_version = "2".encode()
        cipher.server_salt = key.get_serversalt()
        cipher.google_id = key.get_googleid()
        cipher.IV = self.__iv
        from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
        from wa_crypt_tools.proto import key_type_pb2 as key_type
        prefix = prefix.BackupPrefix()
        prefix.key_type = 0
        prefix.c14_cipher.CopyFrom(cipher)

        prefix.info.CopyFrom(props.get_proto())
        prefix = prefix.SerializeToString()
        out = b''
        file_hash = md5()
        out += len(prefix).to_bytes(1, byteorder='big')
        file_hash.update(out)
        if len(props.get_features()) > 0:
            out += b'\x01'
            file_hash.update(b'\x01')
        out += prefix
        file_hash.update(prefix)
        cipher = AES.new(key.get(), AES.MODE_GCM, self.__iv)
        encrypted_data, authentication_tag = cipher.encrypt_and_digest(decrypted)
        out += encrypted_data
        file_hash.update(encrypted_data)
        out += authentication_tag
        file_hash.update(authentication_tag)
        out += file_hash.digest()
        return out


    def __str__(self):
        return f"""cipher_version: {self.cipher_version}
    key_version: {self.key_version}
    serversalt: {self.serversalt}
    googleid: {self.googleid}
    iv: {self.iv}"""


    def get_iv(self) -> bytes:
        return self.__iv


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
            l.debug("Checksum OK ({}). Decrypting...".format(self.file_hash.hexdigest()))

        cipher = AES.new(key.get(), AES.MODE_GCM, self.__iv)
        try:
            output_decrypted: bytes = cipher.decrypt(encrypted_data)
        except ValueError as e:
            l.fatal("Decryption failed: {}."
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
            l.error("Authentication tag mismatch: {}."
                    "\n    This probably means your backup is corrupted.".format(e))

        return output_decrypted
