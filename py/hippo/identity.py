import json

from .rsa import DecryptingKey, SigningKey, CipherText

class PrivateIdentity:
    def __init__(self, decrypting, signing):
        self.decrypting_key = decrypting
        self.signing_key = signing

    @classmethod
    def fromJSON(cls, text):
        if isinstance(text, str):
            text = json.loads(text)
        elif not isinstance(text, dict):
            raise Exception("Expected JSON string or dict")

        if "decrypting" not in text or "signing" not in text:
            raise Exception("Invalid authority identity file")


        decrypting_key = DecryptingKey.fromPEM(text["decrypting"])
        signing_key = SigningKey.fromPEM(text["signing"])


        return PrivateIdentity(decrypting_key, signing_key)

    def decrypt(self, message):
        ciphertext = CipherText.from_json(message)
        return self.decrypting_key.decrypt(ciphertext)
