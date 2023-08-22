from __future__ import annotations

import abc

class Key(abc.ABC):
    @abc.abstractmethod
    def __init__(self, keyarray: bytes = None):
        pass

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def get(self) -> bytes:
        pass

    @abc.abstractmethod
    def dump(self) -> bytes:
        pass
