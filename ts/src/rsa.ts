import {ab2str} from "./strutils"
import * as pem from "./pem"

export class PKCiphertext {
  key: ArrayBuffer
  iv: ArrayBuffer
  text: ArrayBuffer

  constructor(key: ArrayBuffer, iv: ArrayBuffer, text: ArrayBuffer) {
    this.key = key
    this.iv = iv
    this.text = text
  }

  toJSON() : string {
    return JSON.stringify({
      key: window.btoa(ab2str(this.key)),
      iv: window.btoa(ab2str(this.iv)),
      text: window.btoa(ab2str(this.text)),
    });
  }

  // end PKCiphertext
}

export class EncryptingKey {
  readonly key: CryptoKey;

  constructor(key: CryptoKey) {
    this.key = key;
  }

  static async fromPublicKeyPEM(pemdata: string) : Promise<EncryptingKey> {
    const key = await pem.fromPublicKeyPEM(pemdata, "encrypt");
    return new EncryptingKey(key);
  }

  async encrypt(data: ArrayBuffer) : Promise<PKCiphertext> {
    const symkey = await window.crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt"],
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      symkey,
      data
    );

    const exported_symkey = await window.crypto.subtle.exportKey("raw", symkey);

    const encrypted_key = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      this.key,
      exported_symkey,
    );

    return new PKCiphertext(encrypted_key, iv, ciphertext);
  }

  async toPEM() : Promise<string> {
    return pem.toPEM(this.key);
  }

  // end EncryptingKey
}

export class DecryptingKey {
  readonly key: CryptoKeyPair;

  constructor(key: CryptoKeyPair) {
    this.key = key;
  }

  static async generate() : Promise<DecryptingKey> {
    const key = await window.crypto.subtle.generateKey({ name: "RSA-OAEP",
                                                         modulusLength: 4096,
                                                         publicExponent: new Uint8Array([1, 0, 1]),
                                                         hash: "SHA-256",
                                                       },
                                                       true,
                                                       ["encrypt", "decrypt"]
                                                      );
    return new DecryptingKey(key);
  }

  encryptingKey(): EncryptingKey {
    return new EncryptingKey(this.key.publicKey);
  }

  async toPEM() : Promise<string> {
    return pem.toPEM(this.key.privateKey);
  }

  // end DecryptingKey
}


export class SignedText {
  text: ArrayBuffer
  sig: ArrayBuffer

  constructor(text: ArrayBuffer, sig: ArrayBuffer) {
    this.text = text
    this.sig = sig
  }

  toJSON() : string {
    return JSON.stringify({
      text: window.btoa(ab2str(this.text)),
      sig: window.btoa(ab2str(this.sig)),
    });
  }

  // end SignedText
}

export class SigningKey {
  readonly key: CryptoKeyPair;

  constructor(key: CryptoKeyPair) {
    this.key = key;
  }

  /*
  static async fromKey(pemdata: string) : Promise<SigningKey> {
    const key = await pem.fromKeyPEM(pemdata)
    return new SigningKey(key);
  }
  */

  static async generate() : Promise<SigningKey> {
    const key = await window.crypto.subtle.generateKey({ name: "RSA-PSS",
                                                         modulusLength: 4096,
                                                         publicExponent: new Uint8Array([1, 0, 1]),
                                                         hash: "SHA-256",
                                                       },
                                                       true,
                                                       ["sign", "verify"]
                                                      );
    return new SigningKey(key);
  }

  async sign(data: ArrayBuffer) : Promise<SignedText> {
    const sig = await window.crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      this.key.privateKey,
      data,
    );
    return new SignedText(data, sig);
  }

  async toPEM() : Promise<string> {
    return pem.toPEM(this.key.privateKey);
  }

  verifyingKey() : VerifyingKey {
    return new VerifyingKey(this.key.publicKey);
  }

  // end SigningKey
}

export class VerifyingKey {
  readonly key: CryptoKey;

  constructor(key: CryptoKey) {
    this.key = key;
  }

  static async fromPublicKeyPEM(pemdata: string) : Promise<VerifyingKey> {
    const key = await pem.fromPublicKeyPEM(pemdata, "verify");
    return new VerifyingKey(key);
  }

  async toPEM() : Promise<string> {
    return pem.toPEM(this.key);
  }

  // end VerifyingKey
}
