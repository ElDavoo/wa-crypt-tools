import abc
import logging

from wa_crypt_tools.lib.key.key import Key

l = logging.getLogger(__name__)

class Database(abc.ABC):
    iv: bytes

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def get_iv(self) -> bytes:
        pass

    @abc.abstractmethod
    def decrypt(self, key: Key, encrypted: bytes) -> bytes:
        pass

    def encrypt(self, key: Key, decrypted: bytes) -> bytes:
        pass

    def get_iv(self) -> bytes:
        return self.iv
