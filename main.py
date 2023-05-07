# Python3 program to implement XOR - Encryption

# The same function is used to encrypt and
# decrypt
import secrets

import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def read_key_file(file_path):
    with open(file_path, 'r') as file:
        file_contents = file.read()
    return file_contents


def encrypt_decrypt(inp_string, key):
    xor_key = key
    length = len(inp_string)

    for i in range(length):
        inp_string = (inp_string[:i] + chr(ord(inp_string[i]) ^ ord(xor_key[i % len(xor_key)])) + inp_string[i + 1:])
        print(inp_string[i], end="")

    return inp_string


def encrypt_aes_key(aes_key):
    public_key = read_key_file('public.pem')
    encrypter = PKCS1_v1_5.new(RSA.importKey(public_key))
    encrypted_data = encrypter.encrypt(aes_key.encode('utf-8'))
    base64_encoded = base64.b64encode(encrypted_data).decode('utf-8')
    return base64_encoded


def encrypt_text(text, key, iv):
    byte_string = bytes.fromhex(key)
    aesgcm = AESGCM(byte_string)
    iv_byte_string = bytes.fromhex(iv)
    cipher_text = aesgcm.encrypt(iv_byte_string, text.encode('utf-8'), b'')
    return base64.b64encode(cipher_text).decode('utf-8')


# Driver Code
if __name__ == '__main__':
    sampleString = '{"header":{"taxid":"A12Y9504C1C00000000016","indatim":1000000,"indati2m":1000000,"inty":1,"inno":"2","irtaxid":null,"inp":1,"ins":3,"tins":"5555555555","tob":null,"bid":null,"tinb":null,"sbc":null,"bpc":null,"bbc":null,"ft":null,"bpn":null,"scln":null,"scc":null,"crn":null,"billid":null,"tprdis":100,"tdis":0,"tadis":0,"tvam":0,"todam":0,"tbill":0,"setm":1,"cap":100,"insp":100,"tvop":"0","tax17":0},"body":[{"sstid":"1111111111","sstt":"A","am":2,"mu":"23","fee":100,"cfee":null,"cut":null,"exr":null,"prdis":100,"dis":100,"adis":0,"vra":0,"vam":0,"odt":null,"odr":null,"odam":null,"olt":null,"olr":null,"olam":null,"consfee":null,"spro":null,"bros":null,"tcpbs":null,"cop":null,"vop":null,"bsrn":null,"tsstam":100}],"payments":[{"iinn":"1131244211","acn":"2131244212","trmn":"3131244213","trn":"4131244214","pcn":null,"pid":null,"pdt":null}],"extension":null}'

    xorKey = secrets.token_bytes(32).hex()

    # Encrypt the string
    print("Encrypted String: ", end="")
    sampleString = encrypt_decrypt(sampleString, xorKey)
    print("\n")

    # Decrypt the string
    print("Decrypted String: ", end="")
    encrypt_decrypt(sampleString, xorKey)
    print("\n")

    print("encrypt_aes_key: ", end="")
    print(encrypt_aes_key(xorKey))

    print("\n")
    iv = secrets.token_bytes(16).hex()
    print("iv: ", end="")
    print(iv)
    print("\n")

    print("encrypt_data: ", end="")
    print(encrypt_text(sampleString, xorKey, iv))


# This code is contributed by Princi Singh
