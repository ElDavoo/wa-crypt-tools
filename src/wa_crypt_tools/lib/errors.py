"""
The exceptions this library raises.

Everything derives from ValueError, which is what the library used to raise before these
classes existed, so callers that already catch ValueError keep working.

The split that matters is IntegrityError versus the rest. An IntegrityError means a check
failed but a result was still produced, so a caller may knowingly go on with it -- that is
what the tools' --force flag does. Everything else means there is nothing usable to go on
with.
"""


class WaCryptError(ValueError):
    """Base class of every error this library raises deliberately."""


class InvalidKeyError(WaCryptError):
    """The key file, hex string or key parameter cannot be used."""


class ScreenshotKeyError(InvalidKeyError):
    """
    The key could not be read off a screenshot -- OCR is what failed, not the user.

    A subclass rather than a plain InvalidKeyError because the advice differs completely.
    For a key file the answer is "you picked the wrong file"; here the file was right and
    the reader misread it, and the way out is to type the 64 digits in by hand. Callers that
    only catch InvalidKeyError keep working.
    """


class HeaderError(WaCryptError):
    """The database header is missing, truncated or cannot be parsed."""


class DecryptionError(WaCryptError):
    """The cipher itself failed to decrypt the data."""


class IntegrityError(WaCryptError):
    """
    A check failed, but a best-effort result was produced anyway.

    `data` carries that result: the plaintext for a failed authentication tag, the parsed
    Database for a suspect header. It is what --force writes out instead of aborting, so
    that continuing does not mean decrypting a second time. It is None where the result was
    already streamed to the output and there is nothing left to hand back.
    """

    def __init__(self, message, *, data=None):
        super().__init__(message)
        self.data = data
