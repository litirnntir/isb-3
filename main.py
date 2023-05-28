import argparse

from symmetric import *
from asymmetric import *
from workWIthFiles import *

settingsFile = 'settings.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=settingsFile, type=str,
                        help='Allows you to use your own json file with the path'
                             '(Enter path)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', nargs="?", const=256, type=int,
                       help='Starts the key generation mode')
    group.add_argument('-enc', '--encryption', nargs="?", const=256, type=int,
                       help='Launches encryption mode')
    group.add_argument('-dec', '--decryption', nargs="?", const=256, type=int,
                       help='Starts decryption mode')
    args = parser.parse_args()
    settings = loadSettings(args.settings)
    if settings:
        if args.generation:
            symmetric_key = generateSymmetricKey(args.generation)
            private_key, public_key = generateAsymmetricKeys()
            saveAsymmetricKey(private_key, public_key,
                              settings['secret_key'], settings['public_key'])
            cipher_symmetric_key = encryptAsymmetric(
                public_key, symmetric_key)
            saveSymmetricKey(cipher_symmetric_key, settings['symmetric_key'])
        elif args.encryption:
            private_key = loadPrivateKey(settings['secret_key'])
            cipher_key = loadSymmetricKey(settings['symmetric_key'])
            symmetric_key = decryptAsymmetric(private_key, cipher_key)
            text = readText(settings['initial_file'])
            cipher_text = encryptSymmetric(symmetric_key, text, args.encryption)
            writeText(cipher_text, settings['encrypted_file'])
        else:
            private_key = loadPrivateKey(settings['secret_key'])
            cipher_key = loadSymmetricKey(settings['symmetric_key'])
            symmetric_key = decryptAsymmetric(private_key, cipher_key)
            cipher_text = readText(settings['encrypted_file'])
            text = decryptSymmetric(symmetric_key, cipher_text, args.decryption)
            writeText(text, settings['decrypted_file'])
