"""
DatabaseFactory.from_file: the one place in the library that branches on the backup version.
"""

import io

import pytest

from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import HeaderError, IntegrityError


def read(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def as_stream(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(io.BytesIO(data))


def crypt15_header(*, iv: bytes) -> bytes:
    """A crypt15 header carrying an arbitrary IV, so the IV check can be reached."""
    from wa_crypt_tools.proto import backup_prefix_pb2 as prefix
    from wa_crypt_tools.proto import key_type_pb2 as key_type
    header = prefix.BackupPrefix()
    header.key_type_deprecated = key_type.Key_Type.E2EE_DEPRECATED
    header.e2ee_key_data.encryption_iv = iv
    header.backup_metadata.app_version = "2.22.5.13"
    header.backup_metadata.jid_suffix = "67"
    header.backup_metadata.call_log_migration_finished = True
    serialized = header.SerializeToString()
    return len(serialized).to_bytes(1, byteorder='big') + b'\x01' + serialized


class ExplodingStream(io.BufferedReader):
    """A stream that fails where the factory has to cope: on read, or on the crypt12 rewind."""

    def __init__(self, data: bytes, *, fail_on: str):
        super().__init__(io.BytesIO(data))
        self.fail_on = fail_on

    def read(self, *args):
        if self.fail_on == "read":
            raise OSError("the disk went away")
        return super().read(*args)

    def seek(self, *args):
        if self.fail_on == "seek":
            raise OSError("this stream cannot rewind")
        return super().seek(*args)


class TestVersionDispatch:
    @pytest.mark.parametrize("backup, expected", [
        ("tests/res/msgstore.db.crypt15", Database15),
        ("tests/res/msgstore.db.crypt14", Database14),
        ("tests/res/msgstore.db.crypt12", Database12),
    ], ids=["crypt15", "crypt14", "crypt12"])
    def test_the_format_is_picked_from_the_header(self, backup, expected):
        assert isinstance(DatabaseFactory.from_file(as_stream(read(backup))), expected)

    def test_the_header_hash_is_the_md5_of_exactly_the_bytes_consumed(self):
        # decrypt() continues this hash to check the file checksum, so it has to cover the
        # header and nothing else -- one byte too many or too few and every backup looks
        # like a multifile one.
        from hashlib import md5
        data = read("tests/res/msgstore.db.crypt15")
        stream = as_stream(data)
        db = DatabaseFactory.from_file(stream)
        assert db.file_hash.digest() == md5(data[:stream.tell()]).digest()

    def test_the_props_come_off_the_header(self):
        db = DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")))
        assert db.props.get_jid() == "67"
        assert db.props.get_proto().app_version == "2.22.5.13"

    def test_a_backup_without_a_feature_table_is_still_read(self):
        # The 0x01 marker after the size byte is optional; without it the protobuf starts
        # one byte earlier and the header hash must not include a byte that is not there.
        db = DatabaseFactory.from_file(as_stream(read("tests/res/msgstore-noexpiry.db.crypt14")))
        assert isinstance(db, Database14)
        header = db.props.get_proto()
        assert header.app_version == "2.22.5.13"
        assert header.call_log_migration_finished is False


class TestHeaderFailures:
    def test_an_iv_of_the_wrong_length_raises_but_hands_back_the_database(self):
        # --force needs the half-built database: everything except the IV is usable.
        stream = as_stream(crypt15_header(iv=b'\x00' * 8) + b'ciphertext')
        with pytest.raises(IntegrityError, match="IV is not 16 bytes long but is 8") as excinfo:
            DatabaseFactory.from_file(stream)
        salvaged = excinfo.value.data
        assert isinstance(salvaged, Database15)
        assert salvaged.get_iv() == b'\x00' * 8

    def test_a_header_with_no_iv_at_all_falls_through_to_crypt12(self):
        # Neither e2ee_key_data nor wa_provided_key_data set: the factory cannot call it a crypt14/15, so it
        # rewinds and tries the legacy format, which then rejects it on the cipher version.
        with pytest.raises(IntegrityError, match="does not look like a crypt12, 14 or 15"):
            DatabaseFactory.from_file(as_stream(crypt15_header(iv=b'') + b'\xff' * 128))

    def test_a_stream_that_cannot_be_read_raises_a_header_error(self):
        with pytest.raises(HeaderError, match="Reading database header failed"):
            DatabaseFactory.from_file(ExplodingStream(read("tests/res/msgstore.db.crypt15"), fail_on="read"))

    def test_a_stream_that_cannot_rewind_raises_a_header_error(self):
        # Only reached on the crypt12 fallback, which is the one path that needs to go back
        # to byte 0 after having already consumed the header.
        with pytest.raises(HeaderError, match="Could not reset the file pointer"):
            DatabaseFactory.from_file(ExplodingStream(read("tests/res/msgstore.db.crypt12"), fail_on="seek"))


class TestProtobufImportFailures:
    """
    from_file imports the generated protobuf classes lazily and turns the failure into
    advice. The advice is picked by matching on the exception text, which nothing else
    checks, so it is pinned here.
    """

    @staticmethod
    def failing_import(monkeypatch, error: Exception):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("wa_crypt_tools.proto"):
                raise error
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

    def test_an_import_error_is_re_raised_with_the_upgrade_advice(self, monkeypatch, caplog):
        import logging
        # The message protobuf < 3.20 actually produces.
        self.failing_import(monkeypatch, ImportError(
            "cannot import name 'builder' from 'google.protobuf.internal'"))
        with caplog.at_level(logging.ERROR, logger="wa_crypt_tools.lib.db.dbfactory"):
            with pytest.raises(ImportError):
                DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")))
        assert "upgrade the protobuf library" in caplog.text

    def test_a_missing_proto_package_says_where_to_put_it(self, monkeypatch, caplog):
        import logging
        self.failing_import(monkeypatch, ImportError("no module named backup_prefix_pb2"))
        with caplog.at_level(logging.ERROR, logger="wa_crypt_tools.lib.db.dbfactory"):
            with pytest.raises(ImportError):
                DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")))
        assert "proto" in caplog.text

    def test_an_attribute_error_is_re_raised_with_the_upgrade_advice(self, monkeypatch, caplog):
        import logging
        # A too-old protobuf fails inside the generated module rather than on the import.
        self.failing_import(monkeypatch, AttributeError("module 'google.protobuf' has no attribute 'runtime_version'"))
        with caplog.at_level(logging.ERROR, logger="wa_crypt_tools.lib.db.dbfactory"):
            with pytest.raises(AttributeError):
                DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")))
        assert "too old" in caplog.text
