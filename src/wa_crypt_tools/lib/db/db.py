from __future__ import annotations

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
    # Whether the source's header carried any migration-finished feature flag. Informational
    # only -- it does not affect encrypt(), which always sizes the header with a protobuf
    # varint and never writes a byte of its own for this. None when this database was not
    # parsed from a file.
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
