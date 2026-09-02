"""
Database14 and Database15 share everything but the header they write, so they are exercised
together: the IV check, the multifile-backup branch of decrypt, and get_iv.
"""

from __future__ import annotations

import io
import zlib
from hashlib import sha512

import pytest

from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import IntegrityError
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

CASES = [
    pytest.param(Database15, "tests/res/encrypted_backup.key", "tests/res/msgstore.db.crypt15", id="crypt15"),
    pytest.param(Database14, "tests/res/key", "tests/res/msgstore.db.crypt14", id="crypt14"),
]


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def as_stream(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(io.BytesIO(data))


@pytest.mark.parametrize("cls, keyfile, backup", CASES)
class TestHeaderConstruction:
    def test_an_iv_of_the_wrong_length_is_rejected(self, cls, keyfile, backup):
        with pytest.raises(IntegrityError, match="15 bytes long"):
            cls(iv=b"\x00" * 15)

    def test_an_iv_is_generated_when_not_given(self, cls, keyfile, backup):
        assert cls().get_iv() != cls().get_iv()
        assert len(cls().get_iv()) == 16

    def test_get_iv_returns_the_iv_it_was_built_with(self, cls, keyfile, backup):
        iv = bytes(range(16))
        assert cls(iv=iv).get_iv() == iv


@pytest.mark.parametrize("cls, keyfile, backup", CASES)
class TestMultifileBackups:
    """
    A multifile backup has no trailing md5 of the file; the tag sits where the checksum
    would be. decrypt() detects that by the checksum not matching and shifts everything by
    16 bytes -- so the last 16 bytes of ciphertext must still end up in the plaintext.
    """

    def test_a_backup_without_a_checksum_still_decrypts_in_full(self, cls, keyfile, backup):
        key = KeyFactory.new(keyfile)
        stream = as_stream(read(backup)[:-16])
        db = DatabaseFactory.from_file(stream)
        assert isinstance(db, cls)

        decrypted = zlib.decompress(db.decrypt(key, stream.read()))

        assert sha512(decrypted).digest() == sha512(read("tests/res/msgstore.db")).digest()

    def test_a_corrupted_multifile_backup_is_still_caught(self, cls, keyfile, backup):
        key = KeyFactory.new(keyfile)
        data = bytearray(read(backup)[:-16])
        data[-40] ^= 0xFF
        stream = as_stream(bytes(data))
        db = DatabaseFactory.from_file(stream)

        with pytest.raises(IntegrityError, match="Authentication tag mismatch"):
            db.decrypt(key, stream.read())


class TestStr:
    def test_database15(self):
        assert str(Database15()) == "Database15"

    def test_database14_shows_its_iv(self):
        # It used to print Database12's fields, none of which Database14 has, so any attempt
        # to print one died with an AttributeError.
        iv = bytes(range(16))
        assert str(Database14(iv=iv)) == f"Database14(iv: {iv.hex()})"


class TestCrypt14KeyVersionIsCarriedThrough:
    """
    The crypt14 header carries its own key_version, and it is not derivable from anything
    else: the key file stores the version as a raw byte (b'\\x02') while the header spells it
    in ASCII (b'2'), so neither can be computed from the other. Database14.encrypt used to
    write a hardcoded b'2' -- after the CopyFrom that exists precisely to preserve the parsed
    header -- which silently rewrote the field on any backup that said anything else.
    """

    @staticmethod
    def written_header(db: Database14, key) -> object:
        """The header Database14.encrypt actually wrote, parsed back out."""
        from wa_crypt_tools.lib.props import Props

        data = db.encrypt(key, Props(wa_version="2.22.5.13", jid="67", features=None), b"payload")
        return DatabaseFactory.from_file(as_stream(data)).prefix

    def test_a_reference_key_version_survives_re_encryption(self):
        key = KeyFactory.new("tests/res/key")
        reference = DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt14")))
        reference.prefix.wa_provided_key_data.key_version = b"1"

        db = Database14(iv=bytes(range(16)))
        db.prefix = reference.prefix
        db.feature_table = reference.feature_table

        assert self.written_header(db, key).wa_provided_key_data.key_version == b"1"

    def test_a_backup_written_without_a_reference_still_says_2(self):
        # Nothing to copy from, so the default stands -- which is what every crypt14 fixture
        # in tests/res and every backup off a current device carries.
        header = self.written_header(Database14(iv=bytes(range(16))), KeyFactory.new("tests/res/key"))
        assert header.wa_provided_key_data.key_version == b"2"


class TestPasskeyMetadataIsCarriedThrough:
    """
    No fixture backup has passkey_encryption_metadata set: nothing this project has seen uses
    E2EE_PASSKEY (see passkey_encryption_metadata.proto). Database15.encrypt starts the header
    with header.CopyFrom(self.prefix), the same mechanism that dropped crypt14's key_version
    when it was rebuilt from scratch instead -- so this proves the submessage actually survives
    a re-encryption rather than trusting the CopyFrom by inspection.
    """

    @staticmethod
    def written_header(db: Database15, key) -> object:
        """The header Database15.encrypt actually wrote, parsed back out."""
        from wa_crypt_tools.lib.props import Props

        data = db.encrypt(key, Props(wa_version="2.22.5.13", jid="67", features=None), b"payload")
        return DatabaseFactory.from_file(as_stream(data)).prefix

    def test_passkey_encryption_metadata_survives_re_encryption(self):
        from wa_crypt_tools.proto import key_type_pb2 as key_type

        key = KeyFactory.new("tests/res/encrypted_backup.key")
        reference = DatabaseFactory.from_file(as_stream(read("tests/res/msgstore.db.crypt15")))
        reference.prefix.key_type_new = key_type.Key_Type.E2EE_PASSKEY
        meta = reference.prefix.passkey_encryption_metadata
        meta.encapsulated_root_key = "encapsulated-root-key"
        meta.credential_id_deprecated = "credential-id"
        meta.prf_salt_deprecated = bytes(range(8))
        meta.server_cypher_key_version = "1"
        meta.server_cypher_key_account_salt = bytes(range(16))
        meta.server_cypher_key_server_salt = bytes(range(16, 32))
        meta.client_metadata = b"client-metadata"

        db = Database15(iv=bytes(range(16)))
        db.prefix = reference.prefix
        db.feature_table = reference.feature_table

        written = self.written_header(db, key)
        assert written.key_type_new == key_type.Key_Type.E2EE_PASSKEY
        assert written.passkey_encryption_metadata == meta
