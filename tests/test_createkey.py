import os
import zlib

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props
from hashlib import sha512


class TestCreatekey:
    def test_createkey(self):
        key: Key15 = Key15(key=
        bytes.fromhex(
            '6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017'
        ))
        keyb: bytes = key.dump()
        keyb_digest = sha512(keyb).digest()
        with open("tests/res/encrypted_backup.key", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert keyb_digest == orig_check

    def test_createkey14(self):
        key: Key14 = Key14(key=
        bytes.fromhex(
            '3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6'
        ),
            serversalt=bytes.fromhex('cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044'),
            googleid=bytes.fromhex('92683e735c88727eef9486911f3ac6fa'),
            key_version=b'\x02',
            cipher_version=b'\x00\x01')
        keyb: bytes = key.dump()
        keyb_digest = sha512(keyb).digest()
        with open("tests/res/key", 'rb') as f:
            orig_check = sha512(f.read()).digest()
        assert keyb_digest == orig_check
