import base64
import hmac
import json
import math
import zlib
from hashlib import sha256

from Cryptodome.Cipher import AES
from javaobj import JavaByteArray
from javaobj.v2.beans import JavaArray, JavaClassDesc, ClassDescType

import logging

from wa_crypt_tools.lib.constants import C

# FIXME a "utils" file shouldn't have its own logger
l = logging.getLogger(__name__)


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
            l.error("Test decompression: chunk too small")
            return False
        # Decoding can fail if first two bytes are a bad UTF-8 char
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            l.error("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return False
        else:
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
        l.critical("The key file specified does not exist.\n    "
                   "If you tried to specify the key directly, note it should be "
                   "64 characters long and not {} characters long.".format(len(string)))

    barr = None
    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        l.critical("Couldn't convert the hex string.\n    "
                   "Exception: {}".format(e))
    if len(barr) != 32:
        l.error("The key is not 32 bytes long but {} bytes long.".format(len(barr)))
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
    permutations = int(math.ceil(float(output_bytes) / float(32)))
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
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    iv_size = encoded[0]
    if iv_size != 16:
        raise Exception("IV Size is not 16")

    iv = encoded[1:17]
    mac_size = encoded[17]
    if mac_size != 32:
        raise Exception("MAC Size is not 32")

    mac = encoded[18:50]
    encrypted_metadata = encoded[50:]
    # Authentication part
    hmac_auth = hmac.new(key.get_metadata_authentication(), digestmod='sha256')
    hmac_auth.update(iv)
    hmac_auth.update(encrypted_metadata)
    hmac_auth = hmac_auth.digest()
    if hmac_auth != mac:
        raise ValueError("MAC does not match")
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
    media_hash = hmac_n.digest()
    return media_hash


def header_info(header):
    """
    shows all header, information including the feature vector
    FIXME
    """
    string: str = ""
    if header.c15_iv.IV:
        string += "Crypt15 info:\n"
        string += str("Header information in your crypt15 file:")
        string += str("IV: {}\n".format(header.c15_iv.IV.hex()))
    if header.c14_cipher.IV:
        string += str("Header information in your crypt14 file:\n")
        string += str("Cipher version: {}\n".format(header.c14_cipher.cipher_version.hex()))
        string += str("Key version: {}\n".format(header.c14_cipher.key_version.hex()))
        string += str("Server salt: {}\n".format(header.c14_cipher.server_salt.hex()))
        string += str("Google ID: {}\n".format(header.c14_cipher.google_id.hex()))
        string += str("IV: {}\n".format(header.c14_cipher.IV.hex()))
    string += str("Key type: {}\n".format(header.key_type))
    string += str("WhatsApp version: {}\n".format(header.info.app_version))
    #string += str("Device model: {}".format(header.info.device_model))
    string += str("The last two numbers of the user's Jid: {}\n".format(header.info.jidSuffix))
    string += str("Backup version: {}\n".format(header.info.backup_version))
    #string += str("Size of the backup file: {}".format(header.backup_export_file_size))
    features = [n for n in [*range(5, 38), 39] if getattr(header.info, "f_" + str(n)) == True]
    if len(features) > 0:
        string += str("Features: {}\n".format(features))
        string += str("Max feature number: {}\n".format(max(features)))
    else:
        string += str("No feature table found (not a msgstore DB or very old)\n")

    return string
