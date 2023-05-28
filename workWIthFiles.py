import logging
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger()
logger.setLevel('INFO')


def loadSettings(settingsFile: str) -> dict:
    """
    The function reads the settings file
    :arg settingsFile: name of the settings file
    :return: settings
    """
    settings = None
    try:
        with open(settingsFile) as jsonFile:
            settings = json.load(jsonFile)
        logging.info(f' Settings read from file {settingsFile}')
    except OSError as err:
        logging.warning(f' Error when reading settings from a file {settingsFile}\n{err}')
    return settings


def saveAsymmetricKeys(privateKey, publicKey, privatePem: str, publicPem: str) -> None:
    """
    The function stores the private and public key for asymmetric encryption
    :arg privateKey: private key
    :arg publicKey: public key
    :arg privatePem: the name of the private key file
    :arg publicPem: the name of the public key file
    :return: None
    """
    try:
        with open(privatePem, 'wb') as privateOut:
            privateOut.write(privateKey.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.NoEncryption()))
        logging.info(f' The private key was successfully saved to a file {privatePem}')
    except OSError as err:
        logging.warning(f' Error when saving private key to a file {privatePem}\n{err}')
    try:
        with open(publicPem, 'wb') as public_out:
            public_out.write(publicKey.public_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f' The public key was successfully saved to a file {publicPem}')
    except OSError as err:
        logging.warning(f' Error when saving public key to a file {publicPem}\n{err}')
