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
