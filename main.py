# Python3 program to implement XOR - Encryption

# The same function is used to encrypt and
# decrypt
import secrets

import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def read_key_file(file_path):
    with open(file_path, 'r') as file:
        file_contents = file.read()
    return file_contents


def encryptDecrypt(inpString, key):
    xorKey = key
    length = len(inpString)

    # perform XOR operation of key
    # with every character in string
    for i in range(length):
        inpString = (inpString[:i] +
                     chr(ord(inpString[i]) ^ ord(xorKey[i % len(xorKey)])) +
                     inpString[i + 1:])
        print(inpString[i], end="")

    return inpString


def encrypt_aes_key(aes_key):

    public_key = read_key_file('public.pem')
    encrypter = PKCS1_v1_5.new(RSA.importKey(public_key))
    encrypted_data = encrypter.encrypt(aes_key.encode('utf-8'))
    base64_encoded = base64.b64encode(encrypted_data).decode('utf-8')
    return base64_encoded


# Driver Code
if __name__ == '__main__':
    sampleString = "Hamid Purhasani"
    xorKey = secrets.token_bytes(32).hex()

    # Encrypt the string
    print("Encrypted String: ", end="")
    sampleString = encryptDecrypt(sampleString, xorKey)
    print("\n")

    # Decrypt the string
    print("Decrypted String: ", end="")
    encryptDecrypt(sampleString, xorKey)
    print("\n")

    print("encrypt_aes_key: ", end="")
    print(encrypt_aes_key(xorKey))

# This code is contributed by Princi Singh
