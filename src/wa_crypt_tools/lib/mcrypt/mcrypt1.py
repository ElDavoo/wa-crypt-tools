import base64
import hmac
import json
import logging
import os

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.mcrypt.mcrypt import Mcrypt
from wa_crypt_tools.lib.utils import unpad_pkcs5, pad_pcks5


class Mcrypt1(Mcrypt):
    def __init__(self, metadata = None, iv = None, mac = None):
        self.metadata = None
        if metadata is not None and (isinstance(metadata, str) or isinstance(metadata, bytes)):
            """ Encrypted metadata have been given:
            Store IV, MAC and encrypted metadata
            """

            if isinstance(metadata, str):
                encoded = base64.b64decode(metadata)
            elif isinstance(metadata, bytes):
                encoded = metadata
            else:
                raise ValueError("How did you get here?")

            iv_size = encoded[0]
            if iv_size != 16:
                logging.warning("IV Size is not 16")

            self.iv = encoded[1:iv_size + 1]
            mac_size = encoded[iv_size + 1]
            if mac_size != 32:
                logging.warning("MAC Size is not 32")

            self.mac = encoded[iv_size + 1:mac_size + iv_size + 2]
            self.encrypted_metadata = encoded[mac_size + iv_size + 2:]
        elif metadata is not None and isinstance(metadata, dict):
            """
            Decrypted metadata have been given:
            Use given IV and MAC, or generate randomly
            """
            self.metadata = metadata
            if iv is not None:
                if isinstance(iv, str):
                    # convert from hex
                    self.iv = bytes.fromhex(iv)
                elif isinstance(iv, bytes):
                    self.iv = iv
                else:
                    raise ValueError("IV is not a string or bytes")
                if len(self.iv) != 16:
                    logging.warning("IV size is not 16")
            else:
                # generate random IV
                self.iv = os.urandom(16)

            if mac is not None:
                if isinstance(mac, str):
                    # convert from hex
                    self.mac = bytes.fromhex(mac)
                elif isinstance(iv, bytes):
                    self.mac = mac
                else:
                    raise ValueError("MAC is not a string or bytes")
                if len(self.mac) != 32:
                    logging.warning("MAC size is not 16")
            else:
                # generate random MAC
                self.mac = os.urandom(32)
        else:
            raise ValueError("Metadata is not a string, bytes or dict")


    def decrypt_metadata(self, key: Key15 = None):
        """
        Decrypts the metadata of a mcrypt1 file.
        """
        if not key or not isinstance(key, Key15):
            raise ValueError("Key is not a valid Key15 object")
        if not self.encrypted_metadata:
            raise ValueError("Metadata is not set (???)")
        # Authentication part
        hmac_auth = hmac.new(key.get_metadata_authentication(), digestmod='sha256')
        hmac_auth.update(self.iv)
        hmac_auth.update(self.encrypted_metadata)
        hmac_auth = hmac_auth.digest()
        if hmac_auth != self.mac:
            raise ValueError("Authentication error, MAC does not match")

        # Decryption part
        cipher = AES.new(key.get_metadata_encryption(), AES.MODE_CBC, self.iv)
        decrypted_metadata = cipher.decrypt(self.encrypted_metadata)

        # PKCS5Padding is not natively supported
        decrypted_metadata = unpad_pkcs5(decrypted_metadata)

        self.metadata = json.loads(decrypted_metadata.decode('utf-8'))

    def encrypt_metadata(self, key: Key15, metadata) -> str:
        """Not yet implemented"""
        if not key or not isinstance(key, Key15):
            raise ValueError("Key is not a valid Key15 object")
        padded_metadata = pad_pcks5(json.dumps(metadata).encode('utf-8'))

        if not self.metadata:
            raise ValueError("Decrypted metadata not set")
        raise NotImplementedError("Encryption of metadata not yet implemented")


    def decrypt(self, key: Key15, encrypted: bytes) -> bytes:
        raise NotImplementedError("Decryption of mcrypt1 files not yet implemented")

    def encrypt(self, key: Key15, decrypted: bytes) -> bytes:
        raise NotImplementedError("Encryption of mcrypt1 files not yet implemented")

    def __str__(self):
        raise NotImplementedError("Not yet implemented")