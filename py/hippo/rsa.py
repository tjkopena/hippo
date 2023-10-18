import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dataclasses import dataclass
from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class CipherText:
    key: str
    iv: str
    text: str

@dataclass_json
@dataclass
class SignedText:
    sig: str
    text: str


class EncryptingKey:
    def __init__(self, key):
        self.key = key

    def toPEM(self):
        pem = self.key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return str(pem, encoding='utf-8')

class DecryptingKey:
    def __init__(self, key):
        self.key = key

    @classmethod
    def fromPEM(cls, pem):
        key = serialization.load_pem_private_key(bytes(pem, 'utf-8'), None)
        return DecryptingKey(key)

    def decrypt(self, ciphertext):
        key_bits = self.key.decrypt(base64.b64decode(ciphertext.key),
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(),
                                                 label=None))

        iv = base64.b64decode(ciphertext.iv)
        ciphertext = base64.b64decode(ciphertext.text)

        key = AESGCM(key_bits)
        return key.decrypt(iv, ciphertext, None)

    def encrypting_key(self):
        return EncryptingKey(self.key.public_key())

class SigningKey:
    def __init__(self, key):
        self.key = key

    @classmethod
    def fromPEM(cls, pem):
        key = serialization.load_pem_private_key(bytes(pem, 'utf-8'), None)
        return SigningKey(key)

    def verifying_key(self):
        return VerifyingKey(self.key.public_key())

class VerifyingKey:
    def __init__(self, key):
        self.key = key

    @classmethod
    def fromPEM(cls, pem):
        key = serialization.load_pem_public_key(bytes(pem, 'utf-8'), None)
        return VerifyingKey(key)

    def toPEM(self):
        pem = self.key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return str(pem, encoding='utf-8')

    def verify(self, signedtext):
        sig = base64.b64decode(signedtext.sig)
        text = base64.b64decode(signedtext.text)

        self.key.verify(sig,
                        text,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=32,
                        ),
                        hashes.SHA256()
                        )

        return text
