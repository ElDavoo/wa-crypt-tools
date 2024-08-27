from os.path import exists
from os import system, remove
from hashlib import sha512

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory


class TestWaCreateKey:
    def test_no_input(self):
        assert not exists("encrypted_backup.key")
        try:
            assert system("wacreatekey") == 0
            key: Key15 = KeyFactory.from_file("encrypted_backup.key")
        finally:
            # cleanup
            remove("encrypted_backup.key")

    def test_hex_key(self):
        assert not exists("encrypted_backup.key")
        try:
            assert system("wacreatekey --hex 6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017") == 0
            with open("encrypted_backup.key", 'rb') as f:
                keyb_digest = sha512(f.read()).digest()
            with open("tests/res/encrypted_backup.key", 'rb') as f:
                orig_check = sha512(f.read()).digest()
            assert keyb_digest == orig_check
        finally:
            remove("encrypted_backup.key")

    def test_invalid_hex_key(self):
        assert not exists("encrypted_backup.key")
        assert system("wacreatekey --hex invalid") != 0
        assert not exists("encrypted_backup.key")

    def test_invalid_hex_key_length(self):
        assert not exists("encrypted_backup.key")
        assert system("wacreatekey --hex 00") != 0
        assert not exists("encrypted_backup.key")


    #def test_wacreatekey_hex_key_and_14(self):
    #    assert os.system("wacreatekey --hex 6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017 -c14") == 0
    def test_crypt14_key(self):
        assert not exists("key")
        try:
            assert system("wacreatekey -c14"
                      " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                      " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                      " -gi 92683e735c88727eef9486911f3ac6fa"
                      " -kv 2"
                      " -cv 1") == 0
            with open("key", 'rb') as f:
                keyb_digest = sha512(f.read()).digest()
            with open("tests/res/key", 'rb') as f:
                orig_check = sha512(f.read()).digest()
            assert keyb_digest == orig_check
        finally:
            remove("key")
