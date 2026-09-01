"""
The Database abstract base class.

Version-specific behaviour lives in the three subclasses; what the base class guarantees is
that all three of them answer the same four calls.
"""

import inspect

import pytest

from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15

IMPLEMENTATIONS = [Database12, Database14, Database15]


class TestDatabase:
    def test_the_base_class_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            Database()

    def test_a_subclass_that_forgets_a_method_cannot_be_instantiated(self):
        class Database16(Database):
            def __str__(self):
                return "Database16"

            def decrypt(self, key, encrypted):
                return b""

            def encrypt(self, key, props, decrypted):
                return b""

        with pytest.raises(TypeError, match="get_iv"):
            Database16()

    @pytest.mark.parametrize("cls", IMPLEMENTATIONS, ids=lambda c: c.__name__)
    def test_every_format_implements_the_whole_interface(self, cls):
        assert issubclass(cls, Database)
        assert not inspect.isabstract(cls)
        for name in ("__str__", "decrypt", "encrypt", "get_iv"):
            assert getattr(cls, name) is not getattr(Database, name, None)
