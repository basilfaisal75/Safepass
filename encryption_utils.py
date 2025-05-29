
# PBKDF2 key derivation function for turning a user password into a strong aes key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# AES-GCM for authenticated encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Hash algorithms for PBKDF2 using SHA 256
from cryptography.hazmat.primitives import hashes

# standard libraries for randomness and Base64 encoding/decoding
import os
import base64


def derive_key(password: str, salt: bytes) -> bytes:

    # derive a 256-bit AES key from the users login password and a salt
    # param password: The user's login password
    # param salt: A 16-byte random salt
    # return: A 32-byte symmetric key for AES-GCM

    # configure the PBKDF2 parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # use SHA 256 for the HMAC
        length=32,                  # output key length in bytes
        salt=salt,                  # unique salt per password entry
        iterations=100_000,         # number of hash iterations
    )
    # derive and return the key
    return kdf.derive(password.encode())


def encrypt_password(plaintext: str, user_password: str) -> str:

    # encrypt a plaintext password using AES-GCM
    # generate a fresh 16-byte salt
    # derive an AES key from the user's login password + salt
    # generate a 12-byte nonce for GCM.
    # encrypt the plaintext, producing ciphertext + auth tag.
    # param plaintext: The password to encrypt
    # param user_password: The user's login password
    # return: A Base64 string encoding salt+nonce+ciphertext for safe storage

    salt = os.urandom(16)                     # random 16-byte salt
    key = derive_key(user_password, salt)     # derive AES key
    aesgcm = AESGCM(key)                      # create AES-GCM cipher
    nonce = os.urandom(12)                    # unique 12-byte
    ciphertext = aesgcm.encrypt(nonce,
                                plaintext.encode(),
                                None)         # no additional authenticated data
    # combine salt, nonce, and ciphertext into one blob
    data = salt + nonce + ciphertext
    # return as Base64 for storing in text-based DB
    return base64.b64encode(data).decode()


def decrypt_password(enc_b64: str, user_password: str) -> str:

    try:
        # decode the storage blob
        data = base64.b64decode(enc_b64)
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        # rederive the same AES key
        key = derive_key(user_password, salt)
        aesgcm = AESGCM(key)
        # decrypt
        return aesgcm.decrypt(nonce, ct, None).decode()
    except Exception as e:
        # bubble up decryption or integrity errors
        raise e
