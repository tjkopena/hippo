import * as pk from "./rsa"
import * as pem from "./pem"

export class PrivateIdentity {

  readonly decryptingKey : pk.DecryptingKey;
  readonly signingKey : pk.SigningKey;

  constructor(decryptingKey: pk.DecryptingKey, signingKey: pk.SigningKey) {
    this.decryptingKey = decryptingKey;
    this.signingKey = signingKey;
  }

  static async generate() : Promise<PrivateIdentity> {
    const [decrypter, signer] = await Promise.all([
      pk.DecryptingKey.generate(),
      pk.SigningKey.generate(),
    ]);

    return new PrivateIdentity(decrypter, signer);
  }

  publicIdentity(): PublicIdentity {
    return new PublicIdentity(this.decryptingKey.encryptingKey(),
                              this.signingKey.verifyingKey());
  }

  async sign(msg: ArrayBuffer) : Promise<pk.SignedText> {
    return this.signingKey.sign(msg);
  }

  async toJSON(): Promise<string> {
    const [decrypter, signer] = await Promise.all([
      this.decryptingKey.toPEM(),
      this.signingKey.toPEM(),
    ]);

    const identity = {
      decrypting: decrypter,
      signing: signer,
    }

    return JSON.stringify(identity);
  }

  // end PrivateIdentity
}

export class PublicIdentity {

  readonly encryptingKey : pk.EncryptingKey
  readonly verifyingKey : pk.VerifyingKey

  constructor(encryptingKey: pk.EncryptingKey, verifyingKey: pk.VerifyingKey) {
    this.encryptingKey = encryptingKey;
    this.verifyingKey = verifyingKey;
  }

  static async fromJSON(text: string) : Promise<PublicIdentity> {
    const identity = JSON.parse(text);
    if (!identity.hasOwnProperty('encrypting') || !identity.hasOwnProperty('verifying'))
      throw new Error("Text is not a public identity JSON");

    const [encrypter, verifier] = await Promise.all([
      pk.EncryptingKey.fromPublicKeyPEM(identity.encrypting),
      pk.VerifyingKey.fromPublicKeyPEM(identity.verifying)
    ]);

    return new PublicIdentity(encrypter, verifier);
  }

  async toJSON() : Promise<string> {
    const [encrypter, verifier] = await Promise.all([
      this.encryptingKey.toPEM(),
      this.verifyingKey.toPEM(),
    ]);

    const identity = {
      encrypting: encrypter,
      verifying: verifier,
    }

    return JSON.stringify(identity);
  }

  async encrypt(data: ArrayBuffer) : Promise<pk.PKCiphertext> {
    return this.encryptingKey.encrypt(data);
  }

  // end PublicIdentity
}
