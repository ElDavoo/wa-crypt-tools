from hmac import HMAC
from math import ceil

from Cryptodome.Hash import SHA256


def nestedHMACSHA256NoKey(first_iteration_data, message, permutations):
    return nestedHmacSHA256(first_iteration_data, b'\x00'*32, message, permutations)
def nestedHmacSHA256(first_iteration_data, privateHmacSHA256Key, message, permutations):
    hmacSHA256 = HMAC.new(privateHmacSHA256Key, first_iteration_data, SHA256)
    hmacsha256header = hmacSHA256.digest()
    numPermutations = int(ceil(permutations/32.0))
    existingData = b''
    for i in range(1, numPermutations+1):
        hasher = HMAC.new(hmacsha256header, existingData, SHA256)
        hasher.update(message)
        hasher.update(bytes([i]))
        existingData = hasher.digest()
        yield existingData[:permutations]
        permutations -= len(existingData[:permutations])