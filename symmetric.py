import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generate_symmetric_key(length: int) -> str:
    """
    The function generates a symmetric encryption key
    :arg length: key length
    :return: key
    """
    key = None
    if length == 128 or length == 192 or length == 256:
        key = os.urandom(int(length / 8))
        logging.info(
            ' Symmetric encryption key generated')
    else:
        logging.info(
            ' The length of the key is not equal to 128, 192, 256')
    return key


def encrypt_symmetric(key: bytes, text: bytes, length: int) -> bytes:
    """
    The function encrypts the text with the Camellia symmetric encryption algorithm
    :arg length: the length of the key
    :arg text: the text to be encrypted
    :arg key: key
    :return: the encrypted text
    """
    cipher_text = None
    iv = None
    try:
        padder = padding.ANSIX923(length).padder()
        padded_text = padder.update(text) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        logging.info(f' The text is encrypted with the Camellia symmetric encryption algorithm')
    except OSError as err:
        logging.warning(f' Symmetric encryption error {err}')
    return iv + cipher_text


def decrypt_symmetric(key: bytes, cipher_text: bytes, length: int) -> bytes:
    """
    The function decrypts the symmetric encrypted text
    :arg length: key length
    :arg cipher_text: the encrypted text
    :arg key: key
    :return: returns the decrypted text
    """
    unpadded_text = None
    try:
        cipher_text, iv = cipher_text[16:], cipher_text[:16]
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        decrypt = cipher.decryptor()
        text = decrypt.update(cipher_text) + decrypt.finalize()
        unpadder = padding.ANSIX923(length).unpadder()
        unpadded_text = unpadder.update(text) + unpadder.finalize()
        logging.info(f' Text encrypted by Camellia symmetric encryption algorithm decrypted')
    except OSError as err:
        logging.warning(f' Symmetric decryption error {err}')
    return unpadded_text
