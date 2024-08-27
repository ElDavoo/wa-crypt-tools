from os.path import exists
from os import remove
from hashlib import sha512

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

from tests.utils.utils import Propen, cmp_files


class TestWaCreateKey:
    def test_no_input(self):
        assert not exists("encrypted_backup.key")
        try:
            out, ret = Propen("wacreatekey")
            assert ret == 0
            assert "Key file \"encrypted_backup.key\" created." in out
            key: Key15 = KeyFactory.from_file("encrypted_backup.key")
        finally:
            # cleanup
            remove("encrypted_backup.key")

    def test_hex_key(self):
        assert not exists("encrypted_backup.key")
        try:
            out,ret  = Propen("wacreatekey"
                              " --hex 6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017")
            print(out)

            assert ret == 0
            assert "Key file \"encrypted_backup.key\" created." in out
            assert cmp_files("encrypted_backup.key", "tests/res/encrypted_backup.key")
        finally:
            remove("encrypted_backup.key")

    def test_invalid_hex_key(self):
        assert not exists("encrypted_backup.key")
        out, ret = Propen("wacreatekey --hex invalid")
        assert ret != 0
        assert "Key is not in hexadecimal format" in out
        assert not exists("encrypted_backup.key")

    def test_invalid_hex_key_length(self):
        assert not exists("encrypted_backup.key")
        out, ret = Propen("wacreatekey --hex 00")
        assert ret != 0
        assert "Invalid key length" in out
        assert not exists("encrypted_backup.key")

    def test_crypt14_key(self):
        assert not exists("key")
        try:
            out, ret = Propen("wacreatekey -c14"
                      " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                      " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                      " -gi 92683e735c88727eef9486911f3ac6fa"
                      " -kv 2"
                      " -cv 1")
            assert ret == 0
            assert "Key file \"key\" created." in out
            assert cmp_files("key", "tests/res/key")
        finally:
            remove("key")

    def test_custom_output(self):
        assert not exists("custom.key")
        try:
            out, ret = Propen("wacreatekey -o custom.key")
            assert ret == 0
            assert "Key file \"custom.key\" created." in out
            assert exists("custom.key")
        finally:
            remove("custom.key")

    def test_not_overwrite_file(self):
        assert not exists("encrypted_backup.key")
        try:
            Propen("wacreatekey")
            with open("encrypted_backup.key", "rb") as f:
                chksum = sha512(f.read()).digest()
            out, ret = Propen("wacreatekey")
            assert ret != 0
            assert "The output file already exists." in out
            with open("encrypted_backup.key", "rb") as f:
                assert chksum == sha512(f.read()).digest()
        finally:
            # cleanup
            remove("encrypted_backup.key")

    def test_overwrite_file(self):
        assert not exists("encrypted_backup.key")
        try:
            Propen("wacreatekey")
            with open("encrypted_backup.key", "rb") as f:
                chksum = sha512(f.read()).digest()
            out, ret = Propen("wacreatekey -y")
            assert ret == 0
            with open("encrypted_backup.key", "rb") as f:
                assert chksum != sha512(f.read()).digest()
                assert chksum != sha512(f.read()).digest()
        finally:
            # cleanup
            remove("encrypted_backup.key")