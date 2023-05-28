from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generateAsymmetricKeys() -> tuple:
    """
    The function generates keys for asymmetric encryption
    :return: private key and public key
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privateKey = keys
    publicKey = keys.public_key()
    logging.info(' Asymmetric encryption keys are generated')
    return privateKey, publicKey


def encryptAsymmetric(publicKey, text: bytes) -> bytes:
    """
    The function performs asymmetric encryption using the public key
    :arg text: the text to be encrypted
    :arg publicKey: public key
    :return: the encrypted text
    """
    try:
        encryptedText = publicKey.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(), label=None))
        logging.info(f' The text is encrypted with an asymmetric encryption algorithm')
    except OSError as err:
        logging.warning(f' Asymmetric encryption error {err}')
    return encryptedText
