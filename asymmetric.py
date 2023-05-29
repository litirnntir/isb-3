from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generate_asymmetric_keys() -> tuple:
    """
    The function generates keys for asymmetric encryption
    :return: private key and public key
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    logging.info(' Asymmetric encryption keys are generated')
    return private_key, public_key


def encrypt_asymmetric(public_key, text: bytes) -> bytes:
    """
    The function performs asymmetric encryption using the public key
    :arg text: the text to be encrypted
    :arg public_key: public key
    :return: the encrypted text
    """
    encrypted_text = None
    try:
        encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
        logging.info(f' The text is encrypted with an asymmetric encryption algorithm')
    except OSError as err:
        logging.warning(f' Asymmetric encryption error {err}')
    return encrypted_text


def decrypt_asymmetric(private_key, text: bytes) -> bytes:
    """
    The function decrypts the asymmetrically encrypted text, using the private key
    :arg text: the encrypted text
    :arg private_key: private key
    :return: decrypted text
    """
    decrypted_text = None
    try:
        decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
        logging.info(f' Text encrypted by asymmetric encryption algorithm decrypted')
    except OSError as err:
        logging.warning(f' Asymmetric decryption error {err}')
    return decrypted_text
