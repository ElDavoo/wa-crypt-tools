"""
Unit tests for lib/increment.py -- the messages.bin parser -- against hand-built
payloads. No encryption involved here (see tests/tools-invocation/test_waincrement.py
for the decrypt-then-parse path); these exercise the parsing logic directly, including
the degrade-rather-than-raise behavior a reverse-engineered schema needs (issue #129).
"""

import json
import zipfile
from io import BytesIO

import pytest

from wa_crypt_tools.lib.errors import WaCryptError
from wa_crypt_tools.lib.increment import (
    IncrementFormatError,
    is_incremental_backup,
    read_header,
    read_messages,
)
from wa_crypt_tools.proto import WAWebProtobufsHistorySync_pb2 as history_sync_pb2


def _write_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _history_sync_frame(entries):
    hs = history_sync_pb2.HistorySync()
    hs.syncType = 2
    conv = hs.conversations.add()
    conv.ID = entries[0]["remote_jid"] if entries else "unknown@s.whatsapp.net"
    for e in entries:
        hsm = conv.messages.add()
        wmi = hsm.message
        wmi.key.remoteJID = e["remote_jid"]
        wmi.key.fromMe = e["from_me"]
        wmi.key.ID = e["key_id"]
        if e.get("participant"):
            wmi.key.participant = e["participant"]
        wmi.messageTimestamp = e["timestamp"]
        if e.get("text") is not None:
            wmi.message.conversation = e["text"]
        elif e.get("sticker"):
            wmi.message.stickerMessage.SetInParent()
    return hs.SerializeToString()


def _increment_zip(frames, message_counts=0):
    messages_bin = b"".join(_write_varint(len(f)) + f for f in frames)
    header = {
        "header": {"app_version": "2.26.33.76", "format_version": "1.0"},
        "added_messages": {
            "filename": "messages.bin",
            "format": "protobuf",
            "messages_count_on_backup": message_counts,
            "messages_updated": message_counts,
            "messages_deleted": 0,
        },
    }
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("header.json", json.dumps(header))
        zf.writestr("messages.bin", messages_bin)
    return buf.getvalue()


class TestIsIncrementalBackup:
    def test_a_valid_increment_zip_is_recognised(self):
        payload = _increment_zip([_history_sync_frame([])])
        assert is_incremental_backup(payload) is True

    def test_a_plain_sqlite_payload_is_not(self):
        assert is_incremental_backup(b"SQLite format 3\x00" + b"\x00" * 100) is False

    def test_a_zip_without_the_right_names_is_not(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("something_else.txt", "not it")
        assert is_incremental_backup(buf.getvalue()) is False


class TestReadMessages:
    def test_parses_a_text_message(self):
        payload = _increment_zip([_history_sync_frame([
            {"remote_jid": "34600000003@s.whatsapp.net", "from_me": False,
             "key_id": "K1", "timestamp": 1735689600, "text": "hola"},
        ])], message_counts=1)
        messages = list(read_messages(payload))
        assert len(messages) == 1
        m = messages[0]
        assert m.key_id == "K1"
        assert m.chat_jid == "34600000003@s.whatsapp.net"
        assert m.from_me is False
        assert m.sender_jid == "34600000003@s.whatsapp.net"
        assert m.timestamp == 1735689600
        assert m.text == "hola"

    def test_from_me_sender_is_me(self):
        payload = _increment_zip([_history_sync_frame([
            {"remote_jid": "34600000003@s.whatsapp.net", "from_me": True,
             "key_id": "K2", "timestamp": 1735689601, "text": "vale"},
        ])], message_counts=1)
        assert list(read_messages(payload))[0].sender_jid == "me"

    def test_group_message_uses_participant(self):
        payload = _increment_zip([_history_sync_frame([
            {"remote_jid": "1111@g.us", "from_me": False, "key_id": "K3",
             "participant": "34600000009@s.whatsapp.net", "timestamp": 1735689602,
             "text": "hola grupo"},
        ])], message_counts=1)
        assert list(read_messages(payload))[0].sender_jid == "34600000009@s.whatsapp.net"

    def test_media_without_caption_has_no_text(self):
        payload = _increment_zip([_history_sync_frame([
            {"remote_jid": "34600000003@s.whatsapp.net", "from_me": True,
             "key_id": "K4", "timestamp": 1735689603, "sticker": True},
        ])], message_counts=1)
        messages = list(read_messages(payload))
        assert len(messages) == 1
        assert messages[0].text is None

    def test_a_malformed_frame_is_skipped_not_raised(self):
        good = _history_sync_frame([
            {"remote_jid": "34600000003@s.whatsapp.net", "from_me": False,
             "key_id": "K5", "timestamp": 1735689604, "text": "este si vale"},
        ])
        garbage = b"\xff\xff\xff not a valid protobuf frame"
        payload = _increment_zip([garbage, good], message_counts=2)
        messages = list(read_messages(payload))
        assert len(messages) == 1
        assert messages[0].key_id == "K5"

    def test_a_message_missing_key_or_jid_is_skipped(self):
        hs = history_sync_pb2.HistorySync()
        hs.syncType = 2
        conv = hs.conversations.add()
        conv.ID = "unknown@s.whatsapp.net"
        hsm = conv.messages.add()
        hsm.message.key.fromMe = False  # present, but remoteJID/ID left unset
        hsm.message.messageTimestamp = 1735689605
        hsm.message.message.conversation = "sin key ni jid"
        payload = _increment_zip([hs.SerializeToString()], message_counts=1)
        assert list(read_messages(payload)) == []

    def test_not_a_zip_raises_increment_format_error(self):
        with pytest.raises(IncrementFormatError):
            list(read_messages(b"this is not a zip file"))

    def test_increment_format_error_is_a_wacrypterror(self):
        assert issubclass(IncrementFormatError, WaCryptError)


class TestReadHeader:
    def test_reads_the_counts(self):
        payload = _increment_zip([_history_sync_frame([])], message_counts=7)
        header = read_header(payload)
        assert header["added_messages"]["messages_updated"] == 7
