import logging

from wa_crypt_tools.lib.mcrypt.mcrypt1 import Mcrypt1

l = logging.getLogger(__name__)

class McryptFactory:
    @staticmethod
    def from_file(encrypted):

        return Mcrypt1(encrypted)