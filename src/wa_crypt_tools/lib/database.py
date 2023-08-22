import abc
import logging

from google.protobuf.message import DecodeError

from wa_crypt_tools.lib.key import Key14, Key15

l = logging.getLogger(__name__)
from pathlib import Path

from re import findall
from os import urandom


class Database(abc.ABC):
    iv: bytes

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def get_iv(self) -> bytes:
        pass


class Database12(Database):
    # These constants are only used with crypt12/14 keys.
    SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']

    def __init__(self, key: Key14 = None, encrypted=None, file_hash=None,
                 cipher_version: bytes = None, key_version: bytes = None, serversalt: bytes = None,
                 googleid: bytes = None, iv: bytes = None):
        if encrypted and file_hash:
            self.cipher_version = encrypted.read(2)
            # if test_bytes != key.get_cipher_version():
            #    quit_12()
            file_hash.update(self.cipher_version)

            self.key_version = encrypted.read(1)
            # if test_bytes != key.get_key_version():
            #    quit_12()
            file_hash.update(self.key_version)

            self.serversalt = encrypted.read(32)
            # if test_bytes != key.get_serversalt():
            #    quit_12()
            file_hash.update(self.serversalt)

            self.googleid = encrypted.read(16)
            # if test_bytes != key.get_googleid():
            #    quit_12()
            file_hash.update(self.googleid)

            self.iv = encrypted.read(16)
            file_hash.update(self.iv)
        elif key:
            self.cipher_version = key.get_cipher_version()
            self.key_version = key.get_key_version()
            self.serversalt = key.get_serversalt()
            self.googleid = key.get_googleid()
            self.iv = urandom(16)
        else:
            if cipher_version:
                if cipher_version == Database12.SUPPORTED_CIPHER_VERSION:
                    self.cipher_version = cipher_version
                else:
                    l.critical("Unsupported cipher version.")
                    raise ValueError
            else:
                self.cipher_version = Database12.SUPPORTED_CIPHER_VERSION

            if key_version:
                if key_version in Database12.SUPPORTED_KEY_VERSIONS:
                    self.key_version = key_version
                else:
                    l.critical("Unsupported key version.")
                    raise ValueError
            else:
                self.key_version = Database12.SUPPORTED_KEY_VERSIONS[-1]

            if serversalt:
                self.serversalt = serversalt
            else:
                self.serversalt = urandom(32)

            if googleid:
                self.googleid = googleid
            else:
                self.googleid = urandom(16)

            if iv:
                self.iv = iv
            else:
                self.iv = urandom(16)

    def __str__(self):
        return f"""cipher_version: {self.cipher_version}
key_version: {self.key_version}
serversalt: {self.serversalt}
googleid: {self.googleid}
iv: {self.iv}"""

    def write(self, file: Path):
        """Writes the database to a file."""
        with open(file, 'wb') as f:
            f.write(self.cipher_version)
            f.write(self.key_version)
            f.write(self.serversalt)
            f.write(self.googleid)
            f.write(self.iv)

    def get_iv(self) -> bytes:
        return self.iv


class Database14(Database):
    def __init__(self, key: Key14 = None, encrypted=None, file_hash=None,
                 cipher_version: bytes = None, key_version: bytes = None, serversalt: bytes = None,
                 googleid: bytes = None, iv: bytes = None):
        if encrypted and file_hash:
            try:
                from wa_crypt_tools.proto import prefix_pb2 as prefix
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

            self.header = prefix.prefix()

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
                        self.__version = findall(r"\d(?:\.\d{1,3}){3}", self.header.info.whatsapp_version)
                        if len(self.__version) != 1:
                            l.error('WhatsApp version not found')
                        else:
                            l.debug("WhatsApp version: {}".format(self.__version[0]))
                        if len(self.header.info.substringedUserJid) != 2:
                            l.error("The phone number end is not 2 characters long")
                        l.debug("Your phone number ends with {}".format(self.header.info.substringedUserJid))

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

    # overwrite write method
    def write(self, file: Path):
        # Writes a protobuf message
        from wa_crypt_tools.proto import C14_cipher_pb2 as C14_cipher
        cipher = C14_cipher.C14_cipher()
        cipher.key_version = self.key_version
        cipher.server_salt = self.serversalt
        cipher.google_id = self.googleid
        cipher.IV = self.iv
        from wa_crypt_tools.proto import prefix_pb2 as prefix
        from wa_crypt_tools.proto import key_type_pb2 as key_type
        prefix = prefix.prefix()
        prefix.c14_cipher.CopyFrom(cipher)
        prefix.key_type = key_type.WA_PROVIDED
        from wa_crypt_tools.proto import version_features_pb2 as version_features
        version_features = version_features.Version_Features()
        version_features.whatsapp_version = "2.21.11"
        version_features.substringedUserJid = "00"

        prefix.info.CopyFrom(version_features)
        prefix = prefix.SerializeToString()
        print(prefix)
        print(type(prefix))
        with open(file, 'wb') as f:
            f.write(len(prefix).to_bytes(1, 'big'))
            if version_features.HasField("idk"):
                f.write(b'\x01')
            f.write(prefix)

    def __str__(self):
        return f"""cipher_version: {self.cipher_version}
key_version: {self.key_version}
serversalt: {self.serversalt}
googleid: {self.googleid}
iv: {self.iv}"""

    def get_iv(self) -> bytes:
        return self.__iv


class Database15(Database):
    def __str__(self):
        return "Database15"
        # todo

    def __init__(self, key: Key15 = None, encrypted=None, file_hash=None, iv: bytes = None):
        if encrypted and file_hash:
            try:
                from wa_crypt_tools.proto import prefix_pb2 as prefix
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

            self.header = prefix.prefix()

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

                try:

                    protobuf_raw = encrypted.read(protobuf_size)
                    file_hash.update(protobuf_raw)

                    if self.header.ParseFromString(protobuf_raw) != protobuf_size:
                        l.error("Protobuf message not fully read. Please report a bug.")
                    else:

                        # Checking and printing WA version and phone number
                        version = findall(r"\d(?:\.\d{1,3}){3}", self.header.info.whatsapp_version)
                        if len(version) != 1:
                            l.error('WhatsApp version not found')
                        else:
                            l.debug("WhatsApp version: {}".format(version[0]))
                        if len(self.header.info.substringedUserJid) != 2:
                            l.error("The phone number end is not 2 characters long")
                        l.debug("Your phone number ends with {}".format(self.header.info.substringedUserJid))

                        if len(self.header.c15_iv.IV) != 0:
                            # DB Header is crypt15
                            # if type(key) is not Key15:
                            #    l.error("You are using a crypt14 key file with a crypt15 backup.")
                            if len(self.header.c15_iv.IV) != 16:
                                l.error("IV is not 16 bytes long but is {} bytes long".format(len(self.header.c15_iv.IV)))
                            iv = self.header.c15_iv.IV

                        elif len(self.header.c14_cipher.IV) != 0:
                            raise ValueError("Crypt14 file in crypt15 constructor!")
                        else:
                            l.error("Could not parse the IV from the protobuf message. Please report a bug.")
                            raise ValueError



                except DecodeError as e:

                    l.error("Could not parse the protobuf message: {}".format(e))
                    raise e

            except OSError as e:
                l.fatal("Reading database header failed: {}".format(e))
                raise e
        else:
            if iv:
                self.iv = iv
            else:
                self.iv = urandom(16)

    def get_iv(self) -> bytes:
        return self.iv