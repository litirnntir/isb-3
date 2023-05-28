import argparse

from symmetric import *
from asymmetric import *
from workWIthFiles import *

SETTINGS_FILE = 'settings.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=SETTINGS_FILE, type=str,
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
    settings = load_settings(args.settings)
    if settings:
        if args.generation:
            symmetric_key = generate_symmetric_key(args.generation)
            private_key, public_key = generateAsymmetricKeys()
            save_asymmetric_key(private_key, public_key,
                                settings['secret_key'], settings['public_key'])
            cipher_symmetric_key = encryptAsymmetric(
                public_key, symmetric_key)
            save_symmetric_key(cipher_symmetric_key, settings['symmetric_key'])
        elif args.encryption:
            private_key = load_private_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decryptAsymmetric(private_key, cipher_key)
            text = read_text(settings['initial_file'])
            cipher_text = encrypt_symmetric(symmetric_key, text, args.encryption)
            write_text(cipher_text, settings['encrypted_file'])
        else:
            private_key = load_private_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decryptAsymmetric(private_key, cipher_key)
            cipher_text = read_text(settings['encrypted_file'])
            text = decrypt_symmetric(symmetric_key, cipher_text, args.decryption)
            write_text(text, settings['decrypted_file'])
