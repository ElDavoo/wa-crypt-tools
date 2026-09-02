"""
The free functions in lib/utils.py.

They are shared by all three formats and by both key versions, so a change here is a change
to crypt12, 14 and 15 at once -- which is exactly why they are worth pinning down on their own
rather than only through a full decryption.
"""

from __future__ import annotations

import base64
import json
import zlib

import pytest
from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.errors import HeaderError, IntegrityError, InvalidKeyError
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.utils import (
    create_jba,
    encryptionloop,
    get_mcrypt1_name,
    header_info,
    hexstring2bytes,
    javaintlist2bytes,
    mcrypt1_metadata_decrypt,
)
from wa_crypt_tools.lib.utils import (
    test_decompression as decompresses_to_a_database,
)

# Imported under another name: pytest would otherwise collect "test_decompression" itself
# as a test case and fail on its "test_data" argument.

SQLITE = b"SQLite format 3\x00" + b"\x00" * 32


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


class TestUtils:
    # Sample test to test the test infrastructure (!)
    def test_hexstring2bytes(self):
        assert hexstring2bytes("0" * 64) == b"\x00" * 32

    def test_hexstring2bytes_rejects_the_wrong_length(self):
        with pytest.raises(InvalidKeyError) as excinfo:
            hexstring2bytes("00")
        # The message tells the user how long their key actually was; that number is the
        # whole point of the message.
        assert "2 characters" in str(excinfo.value)

    def test_hexstring2bytes_rejects_non_hex(self):
        with pytest.raises(InvalidKeyError):
            hexstring2bytes("z" * 64)

    def test_javaintlist2bytes_undoes_the_sign(self):
        # javaobj hands back Java's signed bytes; 0xFF arrives as -1.
        assert javaintlist2bytes([0, 1, 127, -128, -1]) == b"\x00\x01\x7f\x80\xff"

    def test_create_jba_round_trips_through_javaobj(self):
        import javaobj.v2 as javaobj
        from javaobj import JavaObjectMarshaller

        payload = bytes(range(32))
        dumped = JavaObjectMarshaller().dump(create_jba(payload))
        assert javaintlist2bytes(javaobj.loads(dumped).data) == payload


class TestTestDecompression:
    """The check waguess uses to decide whether a candidate decryption worked."""

    def test_a_zip_is_accepted_without_decompressing(self):
        assert decompresses_to_a_database(read("tests/res/test9.zip")) is True

    def test_a_real_compressed_database_is_accepted(self):
        assert decompresses_to_a_database(read("tests/res/empty-db.zlib1")) is True

    def test_data_that_is_not_zlib_is_rejected(self):
        assert decompresses_to_a_database(b"not compressed at all") is False

    def test_a_chunk_too_small_to_judge_is_rejected(self):
        assert decompresses_to_a_database(zlib.compress(b"tiny")) is False

    def test_compressed_data_that_is_not_sqlite_is_rejected(self):
        assert decompresses_to_a_database(zlib.compress(b"x" * 64)) is False

    def test_a_bad_utf8_start_is_rejected_and_not_raised(self):
        # decode('ascii') on the first 15 bytes is what fails here; it must come back as
        # False rather than escaping as a UnicodeDecodeError.
        assert decompresses_to_a_database(zlib.compress(b"\xff" * 64)) is False

    def test_sqlite_header_is_accepted(self):
        assert decompresses_to_a_database(zlib.compress(SQLITE)) is True

    def test_a_compressed_zip_is_accepted(self):
        # What a real incremental or multi-file backup actually is: a ZIP that WhatsApp then
        # zlib-compresses, so the ZIP header only appears *after* decompression. The check
        # looked for it only before, and so rejected every one of them -- which left waguess
        # unable to find the offsets of a backup it had decrypted perfectly well.
        assert decompresses_to_a_database(zlib.compress(read("tests/res/test9.zip"))) is True


class TestEncryptionLoop:
    """The HMAC-SHA256 loop mirrored in utils/WA_HMACSHA256_Loop.java."""

    def test_the_crypt15_key_derivation(self):
        # The one derivation the library actually depends on: root key -> cipher key.
        root = bytes.fromhex("6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017")
        assert (
            encryptionloop(first_iteration_data=root, message=b"backup encryption", output_bytes=32)
            == Key15(keyarray=root).get()
        )

    def test_it_is_deterministic_and_depends_on_the_message(self):
        root = b"\x01" * 32
        first = encryptionloop(first_iteration_data=root, message=b"backup encryption", output_bytes=32)
        assert first == encryptionloop(first_iteration_data=root, message=b"backup encryption", output_bytes=32)
        assert first != encryptionloop(first_iteration_data=root, message=b"metadata encryption", output_bytes=32)

    def test_more_than_32_bytes_takes_more_than_one_permutation(self):
        # Each round yields 32 bytes, and the first 32 of a longer output are not the same
        # as a 32-byte output: bytestowrite is min(output_bytes, 32), so it is the same
        # prefix only by accident of the truncation, never of the digest.
        out = encryptionloop(first_iteration_data=b"\x02" * 32, message=b"backup encryption", output_bytes=64)
        assert len(out) == 64
        assert out[:32] != out[32:]

    def test_a_None_message_is_allowed(self):
        assert len(encryptionloop(first_iteration_data=b"\x03" * 32, message=None, output_bytes=32)) == 32


class TestMcrypt1:
    """Google Drive E2E metadata, which nothing else in the test suite touches."""

    key = Key15(keyarray=bytes.fromhex("6730a595a1484d0c39c101dc0ac82ec5e401bb6f0e1b8ee2dc104a6b3687f017"))

    @staticmethod
    def make_metadata(key, payload: dict, *, iv_size: int = 16, mac_size: int = 32, corrupt_mac: bool = False) -> str:
        """Builds the base64 blob Google Drive would serve, so it can be decrypted back."""
        import hmac

        plain = json.dumps(payload).encode("utf-8")
        pad = 16 - len(plain) % 16
        plain += bytes([pad]) * pad
        iv = bytes(range(16))
        encrypted = AES.new(key.get_metadata_encryption(), AES.MODE_CBC, iv).encrypt(plain)
        mac = hmac.new(key.get_metadata_authentication(), digestmod="sha256")
        mac.update(iv)
        mac.update(encrypted)
        mac = mac.digest()
        if corrupt_mac:
            mac = bytes(mac[0] ^ 0xFF) + mac[1:]
        return base64.b64encode(bytes([iv_size]) + iv + bytes([mac_size]) + mac + encrypted).decode()

    def test_round_trip(self):
        payload = {"name": "msgstore.db.crypt15", "size": 1234}
        assert mcrypt1_metadata_decrypt(key=self.key, encoded=self.make_metadata(self.key, payload)) == payload

    def test_a_wrong_iv_size_is_rejected(self):
        with pytest.raises(HeaderError, match="IV Size"):
            mcrypt1_metadata_decrypt(key=self.key, encoded=self.make_metadata(self.key, {}, iv_size=12))

    def test_a_wrong_mac_size_is_rejected(self):
        with pytest.raises(HeaderError, match="MAC Size"):
            mcrypt1_metadata_decrypt(key=self.key, encoded=self.make_metadata(self.key, {}, mac_size=16))

    def test_a_mac_that_does_not_match_is_rejected(self):
        with pytest.raises(IntegrityError, match="MAC"):
            mcrypt1_metadata_decrypt(key=self.key, encoded=self.make_metadata(self.key, {}, corrupt_mac=True))

    def test_media_name_is_stable_and_accepts_the_md5_either_way(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        as_hex = get_mcrypt1_name(key=self.key, name="hello", md5=md5)
        as_bytes = get_mcrypt1_name(key=self.key, name="hello", md5=bytes.fromhex(md5))
        assert as_hex == as_bytes
        assert len(as_hex) == 32
        assert as_hex != get_mcrypt1_name(key=self.key, name="goodbye", md5=md5)


class TestHeaderInfo:
    """What wainfo prints. It is only ever logged, so the point is that it says the truth."""

    @staticmethod
    def header_of(path: str):
        from wa_crypt_tools.proto import backup_prefix_pb2 as prefix

        data = read(path)
        size = data[0]
        offset = 2 if data[1] == 1 else 1
        header = prefix.BackupPrefix()
        header.ParseFromString(data[offset : offset + size])
        return header

    def test_crypt15(self):
        header = self.header_of("tests/res/msgstore.db.crypt15")
        string = header_info(header)
        assert "Crypt15 info" in string
        assert header.e2ee_key_data.encryption_iv.hex() in string
        assert "Features: " in string
        assert "Max feature number: 37" in string

    def test_crypt14(self):
        header = self.header_of("tests/res/msgstore.db.crypt14")
        string = header_info(header)
        assert "crypt14" in string
        assert header.wa_provided_key_data.encryption_iv.hex() in string
        assert header.wa_provided_key_data.server_salt.hex() in string

    def test_the_crypt15_iv_is_on_a_line_of_its_own(self):
        # "...in your crypt15 file:" ran straight into "IV: ", unlike the crypt14 branch just
        # below it, so anything reading wainfo's output line by line never saw the IV.
        header = self.header_of("tests/res/msgstore.db.crypt15")
        assert f"IV: {header.e2ee_key_data.encryption_iv.hex()}" in header_info(header).splitlines()

    def test_a_backup_without_a_feature_table(self):
        string = header_info(self.header_of("tests/res/msgstore-noexpiry.db.crypt14"))
        assert "No feature table found" in string
        assert "Features:" not in string
