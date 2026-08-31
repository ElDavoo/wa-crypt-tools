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
    # The header protobuf this database was parsed from, when it was parsed from one.
    # DatabaseFactory sets it; encrypt() rebuilds the header on top of it so that anything
    # WhatsApp put there which this schema does not model survives a re-encryption.
    prefix = None
    # Whether the source carried the 0x01 byte that flags the feature table. None when this
    # database was not parsed from a file, in which case encrypt() falls back to its own rule.
    feature_table = None

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
