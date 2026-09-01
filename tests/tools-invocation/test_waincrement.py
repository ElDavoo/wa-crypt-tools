"""
waincrement: decrypts an incremental backup and reads what's inside messages.bin.

Fixture `tests/res/msgstore-increment-1.db.crypt15` is not a real WhatsApp export -- it
is a hand-built HistorySync protobuf (one conversation, one message) wrapped in the same
ZIP shape (header.json + messages.bin) a real device produces, then encrypted with the
project's own published test key exactly like the other crypt15 fixtures here
(`waencrypt --no-compress --iv 000102030405060708090a0b0c0d0e0f tests/res/
encrypted_backup.key tests/res/increment-messages.zip <out>` -- see tests/res/README or
the PR description for the exact script). See issue #129, proto/NOTICE.md.
"""

import json

from tests.utils.utils import Propen, rm_if_found


class TestWaIncrement:
    def test_reads_the_synthetic_fixture(self):
        out, ret = Propen(
            "waincrement -v tests/res/encrypted_backup.key "
            "tests/res/msgstore-increment-1.db.crypt15")
        assert ret == 0, out
        assert "Messages on backup: 1, updated: 1, deleted: 0" in out
        assert "Parsed 1 message(s)" in out
        assert "hello from an incremental backup fixture" in out

    def test_json_output(self):
        out_path = "waincrement-test-output.json"
        try:
            out, ret = Propen(
                "waincrement tests/res/encrypted_backup.key "
                "tests/res/msgstore-increment-1.db.crypt15 -o " + out_path)
            assert ret == 0, out
            with open(out_path) as f:
                messages = json.load(f)
            assert len(messages) == 1
            assert messages[0]["key_id"] == "TESTKEY1"
            assert messages[0]["chat_jid"] == "34600000003@s.whatsapp.net"
            assert messages[0]["from_me"] is False
            assert messages[0]["text"] == "hello from an incremental backup fixture"
        finally:
            rm_if_found(out_path)

    def test_a_full_snapshot_is_rejected_with_a_clear_message(self):
        # waincrement is for incremental backups specifically -- a plain msgstore.db
        # decrypts fine but is not what this tool reads.
        out, ret = Propen(
            "waincrement tests/res/encrypted_backup.key tests/res/msgstore.db.crypt15")
        assert ret != 0
        assert "wadecrypt instead" in out
