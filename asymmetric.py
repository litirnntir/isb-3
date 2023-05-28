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


