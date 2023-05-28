import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generateSymmetricKey(length: int) -> str:
    """
    The function generates a symmetric encryption key
    :arg length: key length
    :return: key
    """
    key = 0
    if length == 128 or length == 192 or length == 256:
        key = os.urandom(int(length / 8))
        logging.info(
            ' Symmetric encryption key generated')
    else:
        logging.info(
            ' The length of the key is not equal to 128, 192, 256')
    return key