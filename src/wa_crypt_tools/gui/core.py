"""
Everything the GUI decides, with no widgets in it.

app.py is wiring; this is the part that can be wrong, so it is the part that is tested. The
split is not decorative: a Tk test needs a display, and none of what is here does.

Two rules shape this module. It calls the tools in-process rather than shelling out, because a
frozen binary has no `wadecrypt` on PATH -- and because `wadecrypt.decrypt` already holds the
awkward, well-tested parts (the chunked low-memory path, the --force salvage, the zlib-versus-
ZIP sniffing) that a GUI has no business reimplementing. And it never speaks in exception
class names: every failure a user can cause is turned into a sentence that says what to do
about it.
"""

from __future__ import annotations

import logging
import os
import queue
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from wa_crypt_tools import wadecrypt, waguess
from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import (
    DecryptionError,
    HeaderError,
    IntegrityError,
    InvalidKeyError,
    WaCryptError,
)
from wa_crypt_tools.lib.utils import header_info

# The suffixes WhatsApp writes. Anything else keeps its whole name and gains ".decrypted",
# rather than having a guessed extension chopped off it.
BACKUP_SUFFIXES = (".crypt12", ".crypt14", ".crypt15")


@dataclass(frozen=True)
class Description:
    """
    What the GUI says about the file the user just picked, at two levels of detail.

    `headline` is the sentence that goes next to the field -- it has to be readable by
    someone who does not know what an IV is. `detail` is header_info's full rendering, which
    is what wainfo prints; it goes in the Messages pane, where it is available without being
    in the way.
    """

    format: str
    headline: str
    detail: str
    warning: str | None = None


def describe_backup(path: str) -> Description:
    """
    Reads a backup's header and says what it is, in the words wainfo would use.

    Raises OSError if the file cannot be read and WaCryptError if it is not a backup at all,
    which is the commonest mistake there is: pointing this at an already-decrypted database.
    """
    try:
        with open(path, "rb") as f:
            return _describe(DatabaseFactory.from_file(f))
    except IntegrityError as e:
        # The header parsed but something about it is off. wainfo reports on the file rather
        # than refusing to, and so does the pane -- with the reason attached.
        if e.data is None:
            raise
        return _describe(e.data, warning=str(e))


def _describe(db, warning: str | None = None) -> Description:
    # Not str(db): Database15.__str__ returns the literal string "Database15". header_info is
    # where the real rendering lives, and until now it was only ever emitted at DEBUG level.
    if db.prefix is None:
        # Crypt12 has no protobuf prefix; its header fields hang off the object, and
        # Database12.__str__ prints them. There is no app version or jid in there to headline.
        return Description("Crypt12", "Crypt12 backup", str(db), warning)
    fmt = "Crypt15" if db.prefix.e2ee_key_data.encryption_iv else "Crypt14"
    return Description(fmt, _headline(fmt, db.prefix), header_info(db.prefix).strip(), warning)


def _headline(fmt: str, prefix) -> str:
    """
    One line a non-technical user can read.

    header_info's own output opens with three lines that all say "crypt15" and goes on to key
    types and feature numbers -- the right thing for wainfo, far too much to put beside a form
    field. This keeps the two facts that tell someone whether they picked the right file.
    """
    meta = prefix.backup_metadata
    facts = []
    if meta.app_version:
        facts.append(f"WhatsApp {meta.app_version}")
    if meta.jid_suffix:
        facts.append(f"phone number ending {meta.jid_suffix}")
    return f"{fmt} backup" + (" — " + ", ".join(facts) if facts else "")


def suggest_output(encrypted_path: str) -> str:
    """The name to pre-fill the output field with, so the user touches two controls, not three."""
    if not encrypted_path:
        return ""
    p = Path(encrypted_path)
    for suffix in BACKUP_SUFFIXES:
        if p.name.lower().endswith(suffix):
            return str(p.with_name(p.name[: -len(suffix)]))
    return encrypted_path + ".decrypted"


def problems(*, key: str, key_is_file: bool, encrypted: str, output: str, overwrite: bool) -> list[str]:
    """
    Everything wrong with the form, in plain sentences, before any file is opened.

    All of them at once: one trip to the user rather than one per mistake.
    """
    found: list[str] = []
    found.extend(_key_problems(key, key_is_file))

    if not encrypted.strip():
        found.append("Choose the encrypted backup you want to decrypt.")
    elif not Path(encrypted).is_file():
        found.append(f"That backup file does not exist: {encrypted}")

    if not output.strip():
        found.append("Choose where to save the decrypted file.")
    elif encrypted.strip() and _same_file(encrypted, output):
        # Ticking Overwrite must not turn the source into the destination.
        found.append("That would overwrite the backup you are decrypting. Pick a different name for the decrypted file.")
    elif Path(output).is_file() and not overwrite:
        found.append(f'{Path(output).name} already exists. Tick "Overwrite the output file" under Advanced to replace it.')
    return found


def _key_problems(key: str, key_is_file: bool) -> list[str]:
    if not key.strip():
        return ["Choose your key file." if key_is_file else "Paste your 64-character key."]
    if key_is_file:
        if not Path(key).is_file():
            return [f"That key file does not exist: {key}"]
        return []
    # A key transcribed off a screenshot usually arrives in groups, so whitespace is not a
    # mistake worth reporting.
    cleaned = "".join(key.split())
    if len(cleaned) != 64:
        return [f"A key is 64 characters long; this one is {len(cleaned)}."]
    try:
        bytes.fromhex(cleaned)
    except ValueError:
        return ["That key contains characters that are not 0-9 or a-f."]
    return []


def _same_file(a: str, b: str) -> bool:
    try:
        return Path(a).resolve() == Path(b).resolve()
    except OSError:
        return False


def friendly(error: BaseException) -> str:
    """
    The sentence to show the user, taken from the answers already written in the README FAQ.

    Never a class name: a dialog reading "IntegrityError" helps nobody.
    """
    if isinstance(error, IntegrityError):
        return (
            "This backup did not pass its integrity check: it is damaged, or this is not "
            'the right key for it.\n\nUnder Advanced you can tick "Write the output even '
            'if the checks fail" to save the result anyway -- but nothing vouches for it '
            "being your data."
        )
    if isinstance(error, InvalidKeyError):
        return (
            "That key could not be used.\n\nMake sure you picked the key file -- it is "
            'called "encrypted_backup.key", or just "key" for older backups -- and '
            "not the backup itself."
        )
    if isinstance(error, HeaderError):
        return (
            "That file does not look like a WhatsApp backup.\n\nAre the two files the "
            "right way round? The backup is the .crypt12, .crypt14 or .crypt15 file."
        )
    if isinstance(error, DecryptionError):
        return (
            "Decryption failed: the key does not match this backup.\n\nA key belongs to "
            "one account. A key from a different phone, or a newer key after WhatsApp "
            "changed it, will not open this file."
        )
    if isinstance(error, WaCryptError):
        return str(error)
    if isinstance(error, OSError):
        # filename is the useful half; strerror without it reads as a riddle.
        if error.filename:
            return f"{error.strerror or error.__class__.__name__}: {error.filename}"
        return str(error)
    return str(error) or error.__class__.__name__


class QueueLogHandler(logging.Handler):
    """
    Puts log records on a queue for the Tk main loop to drain.

    Tk may only be touched from the thread running its main loop, and the decryption runs on
    a worker, so the records cannot go straight into a text widget.
    """

    def __init__(self, records: queue.Queue, verbose: bool = False):
        super().__init__(level=logging.DEBUG if verbose else logging.INFO)
        self.records = records
        # No CustomFormatter here: its ANSI colour codes would land in the pane as mojibake.
        self.setFormatter(logging.Formatter("%(filename)s:%(lineno)d: %(message)s" if verbose else "%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.put((record.levelno, self.format(record)))
        # A handler that raises breaks the call that logged, which is the one thing emit()
        # must never do; handleError is the documented way out.
        except Exception:  # noqa: BLE001  # pragma: no cover - the queue is unbounded
            self.handleError(record)


@contextmanager
def captured_logs(records: queue.Queue, verbose: bool = False):
    """
    Routes the library's logging into `records` for the duration.

    One handler on "wa_crypt_tools" catches both the lib loggers and the tool modules by
    propagation. Deliberately not lib.logformat.setup_logging, which installs a colour
    StreamHandler onto stderr -- a windowed binary has no stderr worth writing to.
    """
    logger = logging.getLogger("wa_crypt_tools")
    handler = QueueLogHandler(records, verbose)
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def run_decrypt(
    *,
    key: str,
    encrypted: str,
    output: str,
    force: bool = False,
    overwrite: bool = False,
    no_decompress: bool = False,
    low_memory: bool = False,
    try_harder: bool = False,
) -> None:
    """
    Decrypts, raising WaCryptError on failure.

    `key` is a key file path or the 64-character key itself -- KeyFactory tells them apart, so
    the GUI does not have to.
    """
    if try_harder:
        _run_guess(key=key, encrypted=encrypted, output=output, overwrite=overwrite)
        return
    with open(encrypted, "rb") as stream:
        wadecrypt.decrypt(
            SimpleNamespace(
                keyfile=key,
                encrypted=stream,
                decrypted=output,
                no_mem=low_memory,
                buffer_size=None,
                no_decompress=no_decompress,
                force=force,
                yes=overwrite,
            )
        )


def _run_guess(*, key: str, encrypted: str, output: str, overwrite: bool) -> None:
    """
    The "try harder" path, staged through a temporary file.

    waguess opens its output for writing before it knows whether it can decrypt anything at
    all, so a failure would otherwise leave the user an empty file that looks like a result --
    and, with Overwrite ticked, would already have destroyed what was there.
    """
    if Path(output).is_file() and not overwrite:
        raise WaCryptError("The output file already exists.")
    partial = Path(output).with_name(Path(output).name + ".part")
    try:
        with open(encrypted, "rb") as stream, open(partial, "wb") as out:
            waguess.guess(
                SimpleNamespace(
                    keyfile=key,
                    encrypted=stream,
                    decrypted=out,
                    iv_offset=C.DEFAULT_IV_OFFSET,
                    data_offset=C.DEFAULT_DATA_OFFSET,
                )
            )
        os.replace(partial, output)
    finally:
        # os.replace already moved it on the happy path; this is the failure one.
        partial.unlink(missing_ok=True)
