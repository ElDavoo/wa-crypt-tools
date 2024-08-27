from os.path import exists
from hashlib import sha512

from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

from tests.utils.utils import Propen, cmp_files, rmifound


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
            rmifound("encrypted_backup.key")

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
            rmifound("encrypted_backup.key")

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

    def test_custom_output(self):
        assert not exists("custom.key")
        try:
            out, ret = Propen("wacreatekey -o custom.key")
            assert ret == 0
            assert "Key file \"custom.key\" created." in out
            assert exists("custom.key")
        finally:
            rmifound("custom.key")

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
            rmifound("encrypted_backup.key")

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
            rmifound("encrypted_backup.key")

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
            rmifound("key")

    def call_wacreatekey_14(self, arguments):
        assert not exists("key")
        try:
            out, ret = Propen(arguments)
            assert ret == 0
            key = KeyFactory.from_file("key")
            return out
        finally:
            rmifound("key")

    def test_crypt14_key_not_all_parameters(self):
        arguments=["wacreatekey", "-c14", "--hex",
                   "3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6",
                    "-ss", "cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044",
                    "-gi", "92683e735c88727eef9486911f3ac6fa",
                    "-kv", "2",
                    "-cv", "1"]
        # call without key
        self.call_wacreatekey_14(arguments[:2] + arguments[4:])
        # call without server salt
        self.call_wacreatekey_14(arguments[:4] + arguments[6:])
        # without google id
        self.call_wacreatekey_14(arguments[:6] + arguments[8:])
        # without key version
        self.call_wacreatekey_14(arguments[:8] + arguments[10:])
        # without cipher version
        self.call_wacreatekey_14(arguments[:10])
        # Some AI generated combinations below
        self.call_wacreatekey_14(arguments[:2] + arguments[4:6] + arguments[8:])
        self.call_wacreatekey_14(arguments[:2] + arguments[4:8] + arguments[10:])
        self.call_wacreatekey_14(arguments[:2] + arguments[4:10])
        self.call_wacreatekey_14(arguments[:2] + arguments[6:8] + arguments[10:])
        self.call_wacreatekey_14(arguments[:2] + arguments[6:10])
        self.call_wacreatekey_14(arguments[:2] + arguments[8:10])
        self.call_wacreatekey_14(arguments[:4] + arguments[6:8] + arguments[10:])
        self.call_wacreatekey_14(arguments[:4] + arguments[6:10])
        self.call_wacreatekey_14(arguments[:4] + arguments[8:10])
        self.call_wacreatekey_14(arguments[:6] + arguments[8:10])

    def test_crypt14_invalid_server_salt(self):
        assert not exists("key")
        try:
            out, ret = Propen("wacreatekey -c14"
                              " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                              " -ss invalid"
                              " -gi 92683e735c88727eef9486911f3ac6fa"
                              " -kv 2"
                              " -cv 1")
            assert ret != 0
            assert "Something was not right" in out
            assert not exists("key")
        finally:
            rmifound("key")

    def test_crypt14_invalid_google_id(self):
        assert not exists("key")
        try:
            out, ret = Propen("wacreatekey -c14"
                              " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                              " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                              " -gi invalid"
                              " -kv 2"
                              " -cv 1")
            assert ret != 0
            assert "Something was not right" in out
        finally:
            rmifound("key")
        assert not exists("key")

    def test_crypt14_invalid_google_id_length(self):
        assert not exists("key")
        try:
            out, ret = Propen("wacreatekey -c14"
                          " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                          " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                          " -gi 92683e7eef9486911f3ac6fa00"
                          " -kv 2"
                          " -cv 1")
            assert ret != 0
            # assert "Invalid google id length" in out
            assert not exists("key")
        finally:
            rmifound("key")

    def test_crypt14_invalid_key_version(self):
        assert not exists("key")
        try:
            out, ret = Propen("wacreatekey -c14"
                          " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                          " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                          " -gi 92683e735c88727eef9486911f3ac6fa"
                          " -kv invalid"
                          " -cv 1")
            assert ret != 0
            #assert "usage:" in out
            assert not exists("key")
        finally:
            rmifound("key")

    def test_crypt14_invalid_cipher_version(self):
        assert not exists("key")
        out, ret = Propen("wacreatekey -c14"
                          " --hex 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6"
                          " -ss cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044"
                          " -gi 92683e735c88727eef9486911f3ac6fa"
                          " -kv 2"
                          " -cv invalid")
        assert ret != 0
        assert "usage:" in out
        assert not exists("key")
