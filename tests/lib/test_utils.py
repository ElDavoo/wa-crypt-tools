from wa_crypt_tools.lib.utils import hexstring2bytes


class Test_Utils:
    # Sample test to test the test infrastructure (!)
    def test_hexstring2bytes(self):
        assert hexstring2bytes("0"*64) == b'\x00' * 32
