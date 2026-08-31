"""
Reads the messages inside a decrypted incremental backup.

`msgstore-increment-N.db.crypt15` decrypts (via the normal `Database.decrypt()` path --
nothing here changes that) to a ZIP, not a SQLite database: `header.json` (counts),
`messages.bin` (new/changed messages, length-delimited protobuf), and one JSON diff file
per changed table (`chat_modified_1.json`, `jid_modified_1.json`, ...). Only
`messages.bin` is read here; the per-table diffs are out of scope (see `waincrement.py`'s
module docstring and issue #129).

The protobuf schema (`proto/WAWebProtobufsHistorySync.proto` and its transitive imports,
`proto/NOTICE.md`) is `HistorySync` -- the same wire format WhatsApp Web's own
multi-device history-sync uses. Reverse-engineered, not published by WhatsApp, so a frame
or a message this can't make sense of is skipped rather than raised.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from typing import Iterator, Optional

from wa_crypt_tools.proto import WAWebProtobufsHistorySync_pb2 as history_sync_pb2
from wa_crypt_tools.lib.errors import WaCryptError


class IncrementFormatError(WaCryptError):
    """The decrypted payload does not look like a readable incremental backup."""


@dataclass
class IncrementMessage:
    key_id: str
    chat_jid: str
    from_me: bool
    sender_jid: str
    # Seconds, as HistorySync's messageTimestamp stores it -- NOT the milliseconds a
    # decrypted msgstore.db's own `message.timestamp` column uses. A caller merging both
    # sources into one table has to convert one of them.
    timestamp: int
    text: Optional[str]


def _read_varint(buf: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _split_frames(data: bytes) -> Iterator[bytes]:
    pos = 0
    length = len(data)
    while pos < length:
        try:
            frame_len, pos = _read_varint(data, pos)
        except IndexError:
            return  # truncated varint at the tail -- stop, don't guess
        yield data[pos:pos + frame_len]
        pos += frame_len


def _extract_text(message) -> Optional[str]:
    """Best-effort text from the `Message` payload. None for media with no caption, or
    for a payload shape this does not handle (stickers, locations, calls, ...)."""
    if message.HasField("conversation"):
        return message.conversation
    if message.HasField("extendedTextMessage") and message.extendedTextMessage.HasField("text"):
        return message.extendedTextMessage.text
    for field in ("imageMessage", "videoMessage", "documentMessage"):
        if message.HasField(field):
            media = getattr(message, field)
            if media.HasField("caption"):
                return media.caption
            return None
    return None


def is_incremental_backup(payload: bytes) -> bool:
    """True for a decrypted incremental backup (a ZIP with header.json + messages.bin);
    False for a plain SQLite database (the classic full-snapshot payload) or anything
    else. Lets a caller branch on content rather than on which file it asked for."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            names = set(zf.namelist())
            return "header.json" in names and "messages.bin" in names
    except zipfile.BadZipFile:
        return False


def read_header(payload: bytes) -> dict:
    """The parsed header.json of an incremental backup payload -- counts and the
    WhatsApp version that wrote it. Raises IncrementFormatError if this is not one."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            return json.loads(zf.read("header.json"))
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as e:
        raise IncrementFormatError("Could not read header.json: {}".format(e)) from e


def _read_messages_bin(payload: bytes) -> bytes:
    """Validates the ZIP shape and returns the raw messages.bin bytes, or raises
    IncrementFormatError. Split out of read_messages() to keep its own complexity down."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            names = set(zf.namelist())
            if "header.json" not in names or "messages.bin" not in names:
                raise IncrementFormatError(
                    "Not an incremental backup: missing header.json or messages.bin")
            header = json.loads(zf.read("header.json"))
            added = header.get("added_messages") or {}
            if added and added.get("format") not in (None, "protobuf"):
                raise IncrementFormatError(
                    "Unexpected messages.bin format: {!r}".format(added.get("format")))
            return zf.read("messages.bin")
    except zipfile.BadZipFile as e:
        raise IncrementFormatError("Not a valid ZIP: {}".format(e)) from e


def read_messages(payload: bytes) -> Iterator[IncrementMessage]:
    """Yields every message found in an incremental backup's messages.bin.

    Never raises on a single bad frame or message -- only on the payload as a whole not
    being a readable incremental backup at all (no header.json/messages.bin, or a
    messages.bin format other than protobuf).
    """
    data = _read_messages_bin(payload)

    for frame in _split_frames(data):
        try:
            hs = history_sync_pb2.HistorySync()
            hs.ParseFromString(frame)
        except Exception:
            continue  # unofficial schema -- a frame that doesn't parse is skipped

        for conversation in hs.conversations:
            for history_msg in conversation.messages:
                record = _record_from(history_msg)
                if record is not None:
                    yield record


def _record_from(history_msg) -> Optional[IncrementMessage]:
    wmi = history_msg.message
    key = wmi.key
    if not key.ID or not key.remoteJID:
        return None  # nothing to key a merge on

    if key.fromMe:
        sender_jid = "me"
    elif key.participant:
        sender_jid = key.participant
    else:
        sender_jid = key.remoteJID  # 1-1 chat: the chat partner is the sender

    return IncrementMessage(
        key_id=key.ID,
        chat_jid=key.remoteJID,
        from_me=bool(key.fromMe),
        sender_jid=sender_jid,
        timestamp=wmi.messageTimestamp,
        text=_extract_text(wmi.message),
    )
