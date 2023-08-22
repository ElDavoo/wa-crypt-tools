from unittest import TestCase

from wa_crypt_tools.lib.utils import hexstring2bytes


class Test(TestCase):
    # Sample test to test the test infrastructure (!)
    def test_hexstring2bytes(self):
        self.assertEqual(hexstring2bytes("0"*64), b'\x00' * 32)
