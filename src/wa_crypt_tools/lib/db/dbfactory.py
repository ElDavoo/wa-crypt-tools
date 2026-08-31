import logging

from google.protobuf.message import DecodeError

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.errors import HeaderError, IntegrityError
from wa_crypt_tools.lib.props import Props
from wa_crypt_tools.lib.utils import header_info, unknown_header_fields

log = logging.getLogger(__name__)

from hashlib import md5
from re import findall


class _NotCrypt1415(Exception):
    """
    Internal signal: this header is not a crypt14/15 one, so the file should be retried as a
    crypt12. It deliberately does not derive from WaCryptError -- from_file catches it itself
    to pick the format, and a real header error must never be mistaken for this and swallowed
    into a bogus crypt12 attempt.
    """


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
            # The size of the upcoming protobuf message is itself a protobuf varint: one byte
            # for any header under 128 bytes, which covers every backup this project once saw,
            # until a populated passkey_encryption_metadata pushed one over that line. What
            # looked like a second, separate "msgstore feature table" flag byte (a literal
            # 0x01 right after the size) was never an independent thing -- it is the varint's
            # own mandatory continuation byte for any size in [128, 255], which is always 1.
            # Whether the header actually carries feature flags is content, read off
            # backup_metadata below, not a byte in this prefix.
            protobuf_size = 0
            for shift in range(0, 35, 7):
                size_byte = encrypted.read(1)
                if not size_byte:
                    raise HeaderError("Reading database header failed: file ended while reading "
                                      "the header size.")
                file_hash.update(size_byte)
                byte = size_byte[0]
                protobuf_size |= (byte & 0x7f) << shift
                if not byte & 0x80:
                    break
            else:
                raise HeaderError("The header size varint is too long. Please report a bug.")

            try:

                protobuf_raw = encrypted.read(protobuf_size)
                file_hash.update(protobuf_raw)

                if header.ParseFromString(protobuf_raw) != protobuf_size:
                    raise HeaderError("Protobuf message not fully read: the header claims {} bytes. "
                                      "Please report a bug.".format(protobuf_size))

                # Checking and printing WA version and phone number. Neither is used for
                # anything cryptographic, so a surprise here is worth a message and no more.
                version = findall(r"\d(?:\.\d{1,3}){3}", header.backup_metadata.app_version)
                if len(version) != 1:
                    log.error('WhatsApp version not found')
                else:
                    log.debug("WhatsApp version: {}".format(version[0]))
                if len(header.backup_metadata.jid_suffix) != 2:
                    log.error("The phone number end is not 2 characters long")
                log.debug("Your phone number ends with {}".format(header.backup_metadata.jid_suffix))

                if len(header.e2ee_key_data.encryption_iv) != 0:
                    # DB Header is crypt15
                    iv = header.e2ee_key_data.encryption_iv
                    is_crypt15 = True
                elif len(header.wa_provided_key_data.encryption_iv) != 0:
                    # DB Header is crypt14
                    iv = header.wa_provided_key_data.encryption_iv
                    is_crypt15 = False
                else:
                    # Not a crypt14/15 header at all: fall back to crypt12 below.
                    raise _NotCrypt1415

                # We are done here
                log.debug(header_info(header))

                # Anything the schema cannot name is how a format change announces itself.
                extra = unknown_header_fields(header)
                if extra:
                    log.warning("This header carries {} this schema does not know: {}.\n    "
                                "Your WhatsApp is probably newer than this library. The backup "
                                "still reads, and re-encrypting keeps the field, but please "
                                "report it."
                                .format("a field" if len(extra) == 1 else
                                        "{} fields".format(len(extra)), ", ".join(extra)))

                props = Props(v_features=header.backup_metadata)
                # The database is built even when the IV is the wrong length, so that --force
                # has something to go on with; the caller gets it through IntegrityError.data.
                db = Database15(props=props) if is_crypt15 else Database14(props=props)
                db.iv = iv
                db.file_hash = file_hash
                db.prefix = header
                db.feature_table = len(props.get_features()) > 0
                if len(iv) != 16:
                    raise IntegrityError("IV is not 16 bytes long but is {} bytes long"
                                         .format(len(iv)), data=db)
                return db

            except (DecodeError, _NotCrypt1415):

                # try again as a crypt12
                log.debug("Could not parse the protobuf message as a crypt14/15. Trying as a crypt12...")
                try:
                    encrypted.seek(0)
                except OSError as e:
                    raise HeaderError("Could not reset the file pointer: {}".format(e)) from e
                return Database12(encrypted=encrypted)

        except OSError as e:
            raise HeaderError("Reading database header failed: {}".format(e)) from e
