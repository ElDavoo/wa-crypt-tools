"""
The current on-disk format, exercised against real backups rather than reconstructions.

Every fixture here is a genuine header off a WhatsApp 2.26.34.7 device, kept byte for byte
except for what belongs to its owner. What changed: the payload is the real database with the
schema kept and every row deleted, the last two digits of the phone number are 00, the hash and
salt are counted-up bytes of the right length, and the whole thing is re-encrypted with this
repo's test key. See CLAUDE.md for how they were made.

They exist because reconstructions kept missing things real backups do. `key_type_new` sat
unnoticed in every 2.26 backup until a byte-for-byte comparison went looking, and the fixtures
that predate it cannot catch its like again.
"""

import sqlite3
import zipfile
import zlib
from contextlib import closing

import pytest

from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.props import Props
from wa_crypt_tools.proto import key_type_pb2 as key_type

KEY = "tests/res/encrypted_backup.key"
MSGSTORE = "tests/res/msgstore-2.26.db.crypt15"
WA_DB = "tests/res/wa-2.26.db.crypt15"
INCREMENT = "tests/res/msgstore-increment-2.26.crypt15"

CLASSIC_ZLIB = "zlib-ng" not in zlib.ZLIB_VERSION and "zlib-ng" not in zlib.ZLIB_RUNTIME_VERSION


def plaintext(path: str) -> bytes:
    key = KeyFactory.new(KEY)
    with open(path, "rb") as f:
        db = DatabaseFactory.from_file(f)
        return zlib.decompress(db.decrypt(key, f.read()))


def parsed(path: str):
    with open(path, "rb") as f:
        return DatabaseFactory.from_file(f)


class TestTheyDecrypt:
    def test_a_current_msgstore_is_a_database(self):
        data = plaintext(MSGSTORE)
        assert data[:15] == b"SQLite format 3"

    def test_a_current_non_msgstore_backup_is_a_database_too(self):
        assert plaintext(WA_DB)[:15] == b"SQLite format 3"

    def test_an_incremental_backup_is_a_zip(self, tmp_path):
        # The shape the guessing logic could not see: a ZIP that WhatsApp compressed, so its
        # header only shows up after inflating.
        data = plaintext(INCREMENT)
        assert data[:4] == b"PK\x03\x04"
        archive = tmp_path / "inc.zip"
        archive.write_bytes(data)
        with zipfile.ZipFile(archive) as z:
            assert z.testzip() is None
            assert "header.json" in z.namelist()

    def test_the_msgstore_payload_is_a_sound_database(self, tmp_path):
        db = tmp_path / "msgstore.db"
        db.write_bytes(plaintext(MSGSTORE))
        with closing(sqlite3.connect(db)) as connection:
            cursor = connection.cursor()
            assert cursor.execute("pragma integrity_check").fetchone()[0] == "ok"
            # The real 2.26 schema, with every row removed.
            tables = [r[0] for r in cursor.execute("select name from sqlite_master where type='table'")]
            assert len(tables) > 200
            assert sum(cursor.execute(f'select count(*) from "{t}"').fetchone()[0] for t in tables) == 0


class TestTheHeaderIsCurrent:
    """What these fixtures are for: the header fields that 2022 backups do not have."""

    def test_the_key_type_says_which_kind_of_e2e_key(self):
        header = parsed(MSGSTORE).prefix
        assert header.key_type_new == key_type.Key_Type.E2EE_ENCRYPTION_KEY
        assert header.key_type_deprecated == key_type.Key_Type.E2EE_DEPRECATED

    def test_the_backup_version_is_one(self):
        assert parsed(MSGSTORE).prefix.backup_metadata.backup_version == 1

    def test_every_migration_flag_is_set(self):
        props = parsed(MSGSTORE).props
        assert props.get_features() == [*range(5, 38), 39]

    def test_a_non_msgstore_backup_has_no_feature_table(self):
        db = parsed(WA_DB)
        assert db.feature_table is False
        assert db.props.get_features() == []

    def test_a_non_msgstore_backup_carries_the_encrypted_hash(self):
        # Two fields this library did not model at all until they were read out of the app.
        metadata = parsed(WA_DB).prefix.backup_metadata
        assert len(metadata.backup_encrypted_hash_salt) == 16
        assert len(metadata.backup_encrypted_hash) == 32

    def test_nothing_in_these_headers_is_unknown(self):
        # If WhatsApp adds a field and someone refreshes these fixtures, this fails and the
        # schema gets updated -- which is the whole point of keeping real headers around.
        from wa_crypt_tools.lib.utils import unknown_header_fields

        for path in (MSGSTORE, WA_DB, INCREMENT):
            assert unknown_header_fields(parsed(path).prefix) == []


class TestTheyReEncrypt:
    """A re-encryption has to give the bytes back, unknown fields and feature flag included."""

    @pytest.mark.parametrize("path", [MSGSTORE, WA_DB, INCREMENT])
    def test_a_round_trip_reproduces_the_original(self, path):
        if not CLASSIC_ZLIB:
            pytest.skip("zlib-ng compresses differently, so bytes cannot be compared")
        key = KeyFactory.new(KEY)
        with open(path, "rb") as f:
            db = DatabaseFactory.from_file(f)
            compressed = db.decrypt(key, f.read())
        rebuilt = Database15(iv=db.get_iv())
        rebuilt.prefix = db.prefix
        rebuilt.feature_table = db.feature_table
        out = rebuilt.encrypt(key, Props(v_features=db.prefix.backup_metadata), compressed)
        with open(path, "rb") as f:
            assert out == f.read()
