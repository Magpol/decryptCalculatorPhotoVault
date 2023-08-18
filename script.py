#!/usr/bin/env python
# Decrypt files from Calculator - photo vault - com.hld.anzenbokusucal - https://github.com/Magpol
# https://play.google.com/store/apps/details?id=com.hld.anzenbokusucal&hl=en_US
#
# The keyname/value in share_privacy_safe.xml and the db (sqlcipher) is also decrypted using the key: Rny48Ni8aPjYCnUI

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import argparse
import os

DECRYPTION_KEY="Rny48Ni8aPjYCnUI"

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(key.encode()))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

def decrypt_and_save_files_in_directory(directory_path, key):
    for filename in os.listdir(directory_path):
        encrypted_file_path = os.path.join(directory_path, filename)
        if os.path.isfile(encrypted_file_path):
            try:
                decrypted_data = decrypt_file(encrypted_file_path, key)

                decrypted_file_path = encrypted_file_path+".dec"
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)

                print(f"File decrypted: {encrypted_file_path} -> {decrypted_file_path}")
            except:
                print(f"Error in decrypting: {encrypted_file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt files from Calculator - photo vault - com.hld.anzenbokusucal")
    parser.add_argument("--filedir", "-f", type=str,
                        required=True, help="Path to encrypted files")
    args = parser.parse_args()
    decrypt_and_save_files_in_directory(args.filedir, DECRYPTION_KEY)
