# Python3 program to implement XOR - Encryption

# The same function is used to encrypt and
# decrypt
import secrets


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

# This code is contributed by Princi Singh
