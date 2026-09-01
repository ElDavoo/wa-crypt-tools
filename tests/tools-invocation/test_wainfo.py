"""
wainfo: prints what can be read off a backup or a key file without decrypting anything.

It is the one tool that does nothing but call __str__ on what the factories return, so it is
also the only thing that would notice one of those being wrong. Until these tests existed
none of them ran it at all, and `wainfo <any crypt14>` died with
"AttributeError: 'Database14' object has no attribute 'cipher_version'".
"""

import pytest

from tests.utils.utils import Propen, rm_if_found
from wa_crypt_tools.lib.utils import encode_varint

BAD_IV = "short-iv.db.crypt15"


def make_short_iv_backup():
    """A crypt15 header whose IV is 8 bytes: readable, but not usable for decryption."""
    from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
    from wa_crypt_tools.proto import key_type_pb2 as key_type

    header = prefix.BackupPrefix()
    header.key_type_deprecated = key_type.Key_Type.E2EE_DEPRECATED
    header.e2ee_key_data.encryption_iv = b"\x00" * 8
    header.backup_metadata.app_version = "2.22.5.13"
    header.backup_metadata.jid_suffix = "67"
    header.backup_metadata.call_log_migration_finished = True
    serialized = header.SerializeToString()
    with open(BAD_IV, "wb") as f:
        f.write(encode_varint(len(serialized)) + serialized + b"\xff" * 64)


class TestWaInfoOnBackups:
    @pytest.mark.parametrize(
        "backup, expected",
        [
            ("msgstore.db.crypt15", "Database15"),
            ("msgstore.db.crypt14", "Database14(iv: ea53ceae36ecab50bc331aeb62491625)"),
            ("msgstore.db.crypt12", "cipher_version:"),
        ],
        ids=["crypt15", "crypt14", "crypt12"],
    )
    def test_every_format_can_be_printed(self, backup, expected):
        out, ret = Propen("wainfo tests/res/" + backup)
        assert ret == 0, out
        assert expected in out

    def test_the_header_fields_are_reported(self):
        out, ret = Propen("wainfo tests/res/msgstore.db.crypt15")
        assert ret == 0, out
        assert "WhatsApp version: 2.22.5.13" in out
        assert "The last two numbers of the user's Jid: 67" in out
        assert "Max feature number: 37" in out

    def test_a_backup_without_a_feature_table_says_so(self):
        out, ret = Propen("wainfo tests/res/msgstore-noexpiry.db.crypt14")
        assert ret == 0, out
        assert "No feature table found" in out

    def test_a_file_that_is_not_a_backup_fails(self):
        out, ret = Propen("wainfo tests/res/test.json")
        assert ret != 0
        assert "does not look like a crypt12, 14 or 15 database" in out

    def test_a_broken_header_still_prints_what_could_be_read(self):
        # The whole point of this tool: report on a file that no other tool would accept.
        try:
            make_short_iv_backup()
            out, ret = Propen("wainfo " + BAD_IV)
            assert ret != 0
            assert "IV is not 16 bytes long but is 8" in out
            # ... and the half-built database is printed anyway.
            assert "Database15" in out
        finally:
            rm_if_found(BAD_IV)


class TestWaInfoOnKeys:
    def test_a_crypt15_key(self):
        out, ret = Propen("wainfo -k tests/res/encrypted_backup.key")
        assert ret == 0, out
        assert "Key15(key: 6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017)" in out

    def test_a_crypt14_key_shows_every_field(self):
        out, ret = Propen("wainfo -k tests/res/key")
        assert ret == 0, out
        assert "Key14(key: 3a146d9bbd8b6311d962c71619c0c2cce3ce694ea4a0f3f600e271380e1226c6" in out
        assert "serversalt: cd788b1b4625f50d3fccdeac94e1ff638899733b77a224ff614918363901f044" in out
        assert "googleid: 92683e735c88727eef9486911f3ac6fa" in out
        assert "key_version: 02" in out
        assert "cipher_version: 0001" in out

    def test_a_file_that_is_not_a_key_fails(self):
        out, ret = Propen("wainfo -k tests/res/test.json")
        assert ret != 0
        assert "not a valid Java object" in out

    def test_a_backup_read_as_a_key_fails(self):
        _out, ret = Propen("wainfo -k tests/res/msgstore.db.crypt15")
        assert ret != 0
