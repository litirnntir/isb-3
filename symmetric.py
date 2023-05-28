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


def encryptSymmetric(key: bytes, text: bytes, length: int) -> bytes:
    """
    The function encrypts the text with the Camellia symmetric encryption algorithm
    :arg length: the length of the key
    :arg text: the text to be encrypted
    :arg key: key
    :return: the encrypted text
    """
    iv = 0
    cipherText = 0
    try:
        padder = padding.ANSIX923(length).padder()
        paddedText = padder.update(text) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(paddedText) + encryptor.finalize()
        logging.info(f' The text is encrypted with the Camellia symmetric encryption algorithm')
    except OSError as err:
        logging.warning(f' Symmetric encryption error {err}')
    return iv + cipherText
