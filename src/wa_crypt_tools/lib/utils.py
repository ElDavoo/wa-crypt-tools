import base64
import hmac
import json
import logging
import math
import zlib
from hashlib import sha256

from Cryptodome.Cipher import AES
from javaobj import JavaByteArray
from javaobj.v2.beans import ClassDescType, JavaArray, JavaClassDesc

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.errors import HeaderError, IntegrityError, InvalidKeyError

# FIXME a "utils" file shouldn't have its own logger
log = logging.getLogger(__name__)


def test_decompression(test_data: bytes) -> bool:
    """Returns true if the SQLite header is valid.
    It is assumed that the data are valid.
    (If it is valid, it also means the decryption and decompression were successful.)"""

    # If we get a ZIP file header, return true
    if test_data[:4] == C.ZIP_HEADER:
        return True

    try:
        zlib_obj = zlib.decompressobj().decompress(test_data)
        # These two errors should never happen
        if len(zlib_obj) < 16:
            log.error("Test decompression: chunk too small")
            return False
        # A multi-file or incremental backup is a ZIP that WhatsApp compresses like any
        # other payload, so its header only shows up once we have decompressed. The check
        # above only catches a ZIP stored uncompressed.
        if zlib_obj[:4] == C.ZIP_HEADER:
            return True
        # Decoding can fail if first two bytes are a bad UTF-8 char
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            log.error("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return False
        return True
    except (zlib.error, UnicodeDecodeError):
        return False


def create_jba(out: bytes) -> JavaByteArray:
    """Creates a JavaByteArray object from a bytes array"""
    # Create the classdesc
    cd = JavaClassDesc(ClassDescType.NORMALCLASS)
    cd.name = "[B"
    cd.superclass = None
    cd.serial_version_uid = -5984413125824719648
    cd.desc_flags = 2

    return JavaByteArray(out, classdesc=cd)


def hexstring2bytes(string: str) -> bytes:
    """Converts a hex string into a bytes array"""
    if len(string) != 64:
        raise InvalidKeyError("The key file specified does not exist.\n    "
                              "If you tried to specify the key directly, note it should be "
                              f"64 characters long and not {len(string)} characters long.")

    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        raise InvalidKeyError("Couldn't convert the hex string.\n    "
                              f"Exception: {e}") from e
    return barr


def javaintlist2bytes(barr: JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out


def encryptionloop(*, first_iteration_data: bytes, privateseed: bytes = b'\x00' * 32, message: bytes,
                   output_bytes: int):
    # The private key and the seed are used to create the HMAC key
    privatekey = hmac.new(privateseed, msg=first_iteration_data, digestmod=sha256).digest()

    data = b''
    output = b''
    permutations = math.ceil(output_bytes / 32)
    i = 1
    while i < permutations + 1:
        hasher = hmac.new(privatekey, msg=data, digestmod=sha256)
        if message is not None:
            hasher.update(message)
        hasher.update(i.to_bytes(1, byteorder='big'))
        data = hasher.digest()
        bytestowrite = min(output_bytes, len(data))
        output += data[:bytestowrite]
        i += 1
    return output


def mcrypt1_metadata_decrypt(*, key, encoded: str):
    """
    Decrypts the metadata of a mcrypt1 file.
    :param key: The key used to decrypt the metadata
    :param encoded: The metadata downloaded from Google Drive in base64
    :return: The decrypted JSON
    """
    # Base64 decoding
    encoded = base64.b64decode(encoded)
    # PKCS5Padding is not natively supported
    def unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    iv_size = encoded[0]
    if iv_size != 16:
        raise HeaderError("IV Size is not 16")

    iv = encoded[1:17]
    mac_size = encoded[17]
    if mac_size != 32:
        raise HeaderError("MAC Size is not 32")

    mac = encoded[18:50]
    encrypted_metadata = encoded[50:]
    # Authentication part
    hmac_auth = hmac.new(key.get_metadata_authentication(), digestmod='sha256')
    hmac_auth.update(iv)
    hmac_auth.update(encrypted_metadata)
    hmac_auth = hmac_auth.digest()
    if hmac_auth != mac:
        raise IntegrityError("MAC does not match")
    # Decryption part
    cipher = AES.new(key.get_metadata_encryption(), AES.MODE_CBC, iv)
    decrypted_metadata = cipher.decrypt(encrypted_metadata)
    decrypted_metadata = unpad(decrypted_metadata)
    # Load the JSON
    return json.loads(decrypted_metadata.decode('utf-8'))


def get_mcrypt1_name(*, key, name: str, md5: bytes) -> bytes:
    hmac_n = hmac.new(key.get_root(), digestmod='sha256')
    # Calculate SHA256 of the name
    digest = sha256()
    digest.update(name.encode('utf-8'))
    # Pour it into the HMAC
    hmac_n.update(digest.digest())
    # If md5 is a string, convert it to bytes
    if isinstance(md5, str):
        md5 = bytes.fromhex(md5)
    # Now pour the MD5 into the HMAC
    hmac_n.update(md5)
    return hmac_n.digest()


def encode_varint(value: int) -> bytes:
    """The protobuf varint encoding of a non-negative int, as used for the header's own size
    prefix: one byte for any header under 128 bytes, more above that."""
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def unknown_header_fields(header) -> list[str]:
    """
    Names the fields of a parsed header that this schema does not describe, innermost included.

    A WhatsApp format change shows up here first. Field 6 of BackupPrefix sat in every 2.26
    backup for a long time without anyone noticing, because protobuf keeps what it cannot name
    and hands it back on serialisation -- so nothing broke and nothing said anything either.
    Returns descriptions like "BackupPrefix field 7", empty when the schema covers everything.
    """
    try:
        from google.protobuf.unknown_fields import UnknownFieldSet
    except ImportError:  # pragma: no cover - only on a protobuf too old to have it
        return []

    found: list[str] = []

    def walk(message):
        try:
            unknown = UnknownFieldSet(message)
        except (NotImplementedError, TypeError):  # pragma: no cover - implementation-dependent
            return
        for field in unknown:
            found.append(f"{message.DESCRIPTOR.name} field {field.field_number}")
        for descriptor, value in message.ListFields():
            # is_repeated rather than the old label constant: protobuf 7 dropped label with
            # the move to editions.
            if descriptor.type == descriptor.TYPE_MESSAGE and not descriptor.is_repeated:
                walk(value)

    walk(header)
    return found


def header_info(header):
    """
    shows all header, information including the feature vector
    FIXME
    """
    string: str = ""
    if header.e2ee_key_data.encryption_iv:
        string += "Crypt15 info:\n"
        string += "Header information in your crypt15 file:\n"
        string += str(f"IV: {header.e2ee_key_data.encryption_iv.hex()}\n")
    if header.wa_provided_key_data.encryption_iv:
        cipher = header.wa_provided_key_data
        string += "Header information in your crypt14 file:\n"
        string += str(f"Cipher version: {cipher.backup_cipher_header.hex()}\n")
        string += str(f"Key version: {cipher.key_version.hex()}\n")
        string += str(f"Server salt: {cipher.server_salt.hex()}\n")
        string += str(f"Google ID: {cipher.google_id_salt.hex()}\n")
        string += str(f"IV: {cipher.encryption_iv.hex()}\n")
    string += str(f"Key type: {header.key_type_deprecated}\n")
    string += str(f"WhatsApp version: {header.backup_metadata.app_version}\n")
    #string += str("Device model: {}".format(header.backup_metadata.device_model))
    string += str(f"The last two numbers of the user's Jid: {header.backup_metadata.jid_suffix}\n")
    string += str(f"Backup version: {header.backup_metadata.backup_version}\n")
    #string += str("Size of the backup file: {}".format(header.backup_metadata.backup_export_file_size))
    # The migration flags, by field number: the numbers are what this project has always called
    # features, and the schema is what says which fields are flags rather than metadata.
    features = [f.number for f in header.backup_metadata.DESCRIPTOR.fields
                if f.type == f.TYPE_BOOL and getattr(header.backup_metadata, f.name)]
    if len(features) > 0:
        string += str(f"Features: {features}\n")
        string += str(f"Max feature number: {max(features)}\n")
    else:
        string += "No feature table found (not a msgstore DB or very old)\n"

    return string
