import logging
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger()
logger.setLevel('INFO')


def load_settings(settings_file: str) -> dict:
    """
    The function reads the settings file
    :arg settings_file: name of the settings file
    :return: settings
    """
    settings = None
    try:
        with open(settings_file) as jsonFile:
            settings = json.load(jsonFile)
        logging.info(f' Settings read from file {settings_file}')
    except OSError as err:
        logging.warning(f' Error when reading settings from a file {settings_file}\n{err}')
    return settings


def load_private_key(private_pem: str):
    """
    The function reads the private key from the file
    :arg private_pem: file name
    :return: private key
    """
    private_key = None
    try:
        with open(private_pem, 'rb') as pemIn:
            private_bytes = pemIn.read()
        private_key = load_pem_private_key(private_bytes, password=None)
        logging.info(f' Private key read from file {private_pem}')
    except OSError as err:
        logging.warning(f' Error when reading a private key from a file {private_pem}\n{err}')
    return private_key


def load_symmetric_key(file_name: str) -> bytes:
    """
    The function reads the key for symmetric encryption from the file
    :arg file_name: file name
    :return: key
    """
    try:
        with open(file_name, mode='rb') as key_file:
            key = key_file.read()
        logging.info(f' Symmetric key read from file {file_name}')
    except OSError as err:
        logging.warning(f' Error when reading a symmetric key from a file {file_name}\n{err}')
    return key


def save_symmetric_key(key: bytes, file_name: str) -> None:
    """
    The function stores the key for symmetric encryption
    :arg key: key
    :arg file_name: file name of the key
    :return: None
    """
    try:
        with open(file_name, 'wb') as keyFile:
            keyFile.write(key)
        logging.info(f' Symmetric key successfully saved to a file {file_name}')
    except OSError as err:
        logging.warning(f' Error when saving symmetric key to a file {file_name}\n{err}')


def save_asymmetric_key(private_key, public_key, private_pem: str, public_pem: str) -> None:
    """
    The function stores the private and public key for asymmetric encryption
    :arg private_key: private key
    :arg public_key: public key
    :arg private_pem: the name of the private key file
    :arg public_pem: the name of the public key file
    :return: None
    """
    try:
        with open(private_pem, 'wb') as privateOut:
            privateOut.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                       encryption_algorithm=serialization.NoEncryption()))
        logging.info(f' The private key was successfully saved to a file {private_pem}')
    except OSError as err:
        logging.warning(f' Error when saving private key to a file {private_pem}\n{err}')
    try:
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f' The public key was successfully saved to a file {public_pem}')
    except OSError as err:
        logging.warning(f' Error when saving public key to a file {public_pem}\n{err}')


def read_text(file_name: str) -> bytes:
    """
    The function reads a text file
    :arg file_name: file path
    :return: the text from the file
    """
    try:
        with open(file_name, mode='rb') as text:
            text = text.read()
        logging.info(f' File {file_name} has been read')
    except OSError as err:
        logging.warning(f' Error when reading a file {file_name}\n{err}')
    return text


def write_text(text: bytes, file_name: str) -> None:
    """
    The function writes text to the file
    :arg text: text
    :arg file_name: file path
    :return: None
    """
    try:
        with open(file_name, mode='wb') as file:
            file.write(text)
        logging.info(f' The text is written to a file {file_name}')
    except OSError as err:
        logging.warning(f' Error when writing to a file {file_name}\n{err}')
