import abc
import logging

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props

l = logging.getLogger(__name__)


class Mcrypt(abc.ABC):
    """
    An abstract class that represents a mcrypt file.
    """
    iv: bytes
    mac: bytes

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def decrypt_metadata(self, key: Key15 = None):
        pass

    @abc.abstractmethod
    def encrypt_metadata(self, key: Key15, metadata) -> str:
        pass

    @abc.abstractmethod
    def decrypt(self, key: Key15, encrypted: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def encrypt(self, key: Key15, decrypted: bytes) -> bytes:
        pass
