from unittest import TestCase

from wa_crypt_tools.lib.constants import C


class TestConstants(TestCase):
    def test_zip_header(self):
        self.assertEqual(C.ZIP_HEADER, b'PK\x03\x04')