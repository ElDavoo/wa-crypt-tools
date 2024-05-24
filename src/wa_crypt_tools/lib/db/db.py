import abc
import logging

from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


class Database(abc.ABC):
    """
    An abstract class that represents a database.
    """
    iv: bytes

    @abc.abstractmethod
    def __str__(self):
        pass

    @abc.abstractmethod
    def decrypt(self, key: Key, encrypted: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def encrypt(self, key: Key, props: Props, decrypted: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def get_iv(self) -> bytes:
        return self.iv
