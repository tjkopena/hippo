import json

from .rsa import DecryptingKey, SigningKey, CipherText

class PublicIdentity:
    def __init__(self, encrypting, verifying):
        self.encrypting_key = encrypting
        self.verifying_key = verifying

    def toJSON(self):
        public_identity = {
            "encrypting": self.encrypting_key.toPEM(),
            "verifying": self.verifying_key.toPEM(),
        }

        return json.dumps(public_identity)

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

    def public_identity(self):
        return PublicIdentity(self.decrypting_key.encrypting_key(), self.signing_key.verifying_key())
