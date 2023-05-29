import argparse

from symmetric import generate_symmetric_key, encrypt_symmetric, decrypt_symmetric
from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from workWIthFiles import load_settings, save_symmetric_key, save_asymmetric_key, load_private_key, \
    load_symmetric_key, read_text, write_text

SETTINGS_FILE = 'settings.json'


def generation():
    """
    The function generates a symmetric key
    """
    symmetric_key = generate_symmetric_key(args.generation)
    private_key, public_key = generate_asymmetric_keys()
    save_asymmetric_key(private_key, public_key,
                        settings['secret_key'], settings['public_key'])
    cipher_symmetric_key = encrypt_asymmetric(
        public_key, symmetric_key)
    save_symmetric_key(cipher_symmetric_key, settings['symmetric_key'])


def encryption():
    """
    The function encrypts the text with the Camellia symmetric encryption algorithm
    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = decrypt_asymmetric(private_key, cipher_key)
    text = read_text(settings['initial_file'])
    cipher_text = encrypt_symmetric(symmetric_key, text, args.encryption)
    write_text(cipher_text, settings['encrypted_file'])


def decryption():
    """
    The function decrypts the symmetric encrypted text
    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = decrypt_asymmetric(private_key, cipher_key)
    cipher_text = read_text(settings['encrypted_file'])
    text = decrypt_symmetric(symmetric_key, cipher_text, args.decryption)
    write_text(text, settings['decrypted_file'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=SETTINGS_FILE, type=str,
                        help='Allows you to use your own json file with the path'
                             '(Enter path)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', nargs="?", type=int,
                       help='Starts the key generation mode', choices=[128, 192, 256])
    group.add_argument('-enc', '--encryption', nargs="?", type=int,
                       help='Launches encryption mode', choices=[128, 192, 256])
    group.add_argument('-dec', '--decryption', nargs="?", type=int,
                       help='Starts decryption mode', choices=[128, 192, 256])

    args = parser.parse_args()
    settings = load_settings(args.settings)
    if settings:
        if args.generation:
            generation()
        elif args.encryption:
            encryption()
        else:
            decryption()
