import * as pk from "./rsa"

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

  async toJSON(): Promise<string> {
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

  // end PublicIdentity
}
