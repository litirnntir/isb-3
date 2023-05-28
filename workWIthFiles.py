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


def loadPrivateKey(privatePem: str):
    """
    The function reads the private key from the file
    :arg privatePem: file name
    :return: private key
    """
    privateKey = None
    try:
        with open(privatePem, 'rb') as pemIn:
            private_bytes = pemIn.read()
        privateKey = load_pem_private_key(private_bytes, password=None)
        logging.info(f' Private key read from file {privatePem}')
    except OSError as err:
        logging.warning(f' Error when reading a private key from a file {privatePem}\n{err}')
    return privateKey


def loadSymmetricKey(fileName: str) -> bytes:
    """
    The function reads the key for symmetric encryption from the file
    :arg fileName: file name
    :return: key
    """
    try:
        with open(fileName, mode='rb') as key_file:
            key = key_file.read()
        logging.info(f' Symmetric key read from file {fileName}')
    except OSError as err:
        logging.warning(f' Error when reading a symmetric key from a file {fileName}\n{err}')
    return key


def saveSymmetricKey(key: bytes, fileName: str) -> None:
    """
    The function stores the key for symmetric encryption
    :arg key: key
    :arg fileName: file name of the key
    :return: None
    """
    try:
        with open(fileName, 'wb') as keyFile:
            keyFile.write(key)
        logging.info(f' Symmetric key successfully saved to a file {fileName}')
    except OSError as err:
        logging.warning(f' Error when saving symmetric key to a file {fileName}\n{err}')


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


def readText(fileName: str) -> bytes:
    """
    The function reads a text file
    :arg fileName: file path
    :return: the text from the file
    """
    try:
        with open(fileName, mode='rb') as text:
            text = text.read()
        logging.info(f' File {fileName} has been read')
    except OSError as err:
        logging.warning(f' Error when reading a file {fileName}\n{err}')
    return text


def writeText(text: bytes, fileName: str) -> None:
    """
    The function writes text to the file
    :arg text: text
    :arg fileName: file path
    :return: None
    """
    try:
        with open(fileName, mode='wb') as file:
            file.write(text)
        logging.info(f' The text is written to a file {fileName}')
    except OSError as err:
        logging.warning(f' Error when writing to a file {fileName}\n{err}')
