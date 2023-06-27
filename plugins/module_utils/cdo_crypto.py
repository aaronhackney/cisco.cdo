#!/usr/bin/python3
# Requires: pycryptodome
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class CDOCrypto:
    @staticmethod
    def encrypt_creds(username, password, public_key):
        key = RSA.importKey(base64.b64decode(public_key))
        encryptor = PKCS1_v1_5.new(key)
        return {
            "username": base64.b64encode(encryptor.encrypt(username.encode(encoding="UTF-8"))).decode(),
            "password": base64.b64encode(encryptor.encrypt(password.encode(encoding="UTF-8"))).decode()
        }
