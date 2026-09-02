from __future__ import annotations

import abc
import logging
from typing import Generic, TypeVar

from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)

# Which kind of key this database is encrypted with. crypt12 and crypt14 use a Key14, crypt15
# a Key15, and the two are not interchangeable: Database14.encrypt reaches for
# get_serversalt() and get_googleid(), which only exist on a Key14.
#
# Declared with TypeVar rather than PEP 695's `class Database[K: Key]`, which needs 3.12 and
# would be the only thing in the tree to. It says exactly the same thing.
K = TypeVar("K", bound=Key)


class Database(abc.ABC, Generic[K]):
    """
    An abstract class that represents a database, parameterised by the kind of key it takes.

    Subclasses name that key -- `Database15(Database[Key15])` -- and their decrypt/encrypt then
    narrow to it without violating the base class's contract, which is what a bare `key: Key`
    here could not express.
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
    def decrypt(self, key: K, encrypted: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def encrypt(self, key: K, props: Props, decrypted: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def get_iv(self) -> bytes:
        return self.iv
