import logging

from google.protobuf.message import DecodeError

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.props import Props
from wa_crypt_tools.lib.utils import header_info

log = logging.getLogger(__name__)

from hashlib import md5
from re import findall


class DatabaseFactory:
    @staticmethod
    def from_file(encrypted):
        try:
            from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
            from wa_crypt_tools.proto import key_type_pb2 as key_type
        except ImportError as e:
            log.error("Could not import the proto classes: {}".format(e))
            if str(e).startswith("cannot import name 'builder' from 'google.protobuf.internal'"):
                log.error("You need to upgrade the protobuf library to at least 3.20.0.\n"
                          "    python -m pip install --upgrade protobuf")
            elif str(e).startswith("no module named"):
                log.error("Please download them and put them in the \"proto\" sub folder.")
            raise e
        except AttributeError as e:
            log.error("Could not import the proto classes: {}\n    ".format(e) +
                      "Your protobuf library is probably too old.\n    "
                      "Please upgrade to at least version 3.20.0 , by running:\n    "
                      "python -m pip install --upgrade protobuf")
            raise e

        header = prefix.BackupPrefix()

        log.debug("Parsing database header...")

        try:
            file_hash = md5()
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
                log.debug("No feature table found (not a msgstore DB or very old)")

            try:

                protobuf_raw = encrypted.read(protobuf_size)
                file_hash.update(protobuf_raw)

                if header.ParseFromString(protobuf_raw) != protobuf_size:
                    log.error("Protobuf message not fully read. Please report a bug.")
                else:

                    # Checking and printing WA version and phone number
                    version = findall(r"\d(?:\.\d{1,3}){3}", header.info.app_version)
                    if len(version) != 1:
                        log.error('WhatsApp version not found')
                    else:
                        log.debug("WhatsApp version: {}".format(version[0]))
                    if len(header.info.jidSuffix) != 2:
                        log.error("The phone number end is not 2 characters long")
                    log.debug("Your phone number ends with {}".format(header.info.jidSuffix))

                    if len(header.c15_iv.IV) != 0:
                        # DB Header is crypt15
                        # if type(key) is not Key15:
                        #    l.error("You are using a crypt14 key file with a crypt15 backup.")
                        if len(header.c15_iv.IV) != 16:
                            log.error("IV is not 16 bytes long but is {} bytes long".format(len(header.c15_iv.IV)))
                        iv = header.c15_iv.IV

                    elif len(header.c14_cipher.IV) != 0:

                        # DB Header is crypt14
                        # if type(key) is not Key14:
                        #    l.fatal("You are using a crypt15 key file with a crypt14 backup.")

                        # if key.cipher_version != p.c14_cipher.version.cipher_version:
                        #    l.error("Cipher version mismatch: {} != {}"
                        #    .format(key.cipher_version, p.c14_cipher.cipher_version))

                        # Fix bytes to string encoding key.key_version = (key.key_version[0] + 48).to_bytes(1,
                        # byteorder='big') if key.key_version != p.c14_cipher.key_version: if key.key_version >
                        # p.c14_cipher.key_version: l.error("Key version mismatch: {} != {} .\n    " .format(
                        # key.key_version, p.c14_cipher.key_version) + "Your backup is too old for this key file.\n
                        # " + "Please try using a newer backup.") elif key.key_version < p.c14_cipher.key_version:
                        # l.error("Key version mismatch: {} != {} .\n    " .format(key.key_version,
                        # p.c14_cipher.key_version) + "Your backup is too new for this key file.\n    " + "Please try
                        # using an older backup, or getting the new key.") else: l.error("Key version mismatch: {} !=
                        # {} (?)" .format(key.key_version, p.c14_cipher.key_version)) if key.get_serversalt() !=
                        # p.c14_cipher.server_salt: l.error("Server salt mismatch: {} != {}".format(
                        # key.get_serversalt(), p.c14_cipher.server_salt)) if key.get_googleid() !=
                        # p.c14_cipher.google_id: l.error("Google ID mismatch: {} != {}".format(key.get_googleid(),
                        # p.c14_cipher.google_id))
                        if len(header.c14_cipher.IV) != 16:
                            log.error(
                                "IV is not 16 bytes long but is {} bytes long".format(len(header.c14_cipher.IV)))
                        iv = header.c14_cipher.IV

                    else:
                        log.error("Could not parse the IV from the protobuf message. Please report a bug.")
                        raise DecodeError

                    # We are done here
                    log.debug(header_info(header))

                    props = Props(v_features=header.info)
                    if header.c15_iv.IV:
                        db = Database15(iv=iv, props=props)
                        db.file_hash = file_hash
                        return db
                    elif header.c14_cipher.IV:
                        db = Database14(iv=iv, props=props)
                        db.file_hash = file_hash
                        return db
                    else:
                        log.error("Could not parse the IV from the protobuf message. Please report a bug.")
                        raise DecodeError

            except DecodeError:

                # try again as a crypt12
                log.debug("Could not parse the protobuf message as a crypt14/15. Trying as a crypt12...")
                try:
                    encrypted.seek(0)
                except OSError as e:
                    log.fatal("Could not reset the file pointer: {}".format(e))
                    raise e
                return Database12(encrypted=encrypted)

        except OSError as e:
            log.fatal("Reading database header failed: {}".format(e))
