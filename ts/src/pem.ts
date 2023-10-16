
import {str2ab, ab2str} from "./strutils"

export async function fromPublicKeyPEM(pem: string, use: KeyUsage[]) : Promise<CryptoKey> {

  const SPKI_HEADER = "-----BEGIN PUBLIC KEY-----";
  const SPKI_FOOTER = "-----END PUBLIC KEY-----";

  const b64 = pem.substring(SPKI_HEADER.length,
                            pem.length - SPKI_FOOTER.length - 1);
  const data = str2ab(window.atob(b64))

  return window.crypto.subtle.importKey(
    "spki",
    data,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    use);

}

export async function toPEM(key: CryptoKey) : Promise<string> {

  if (!key.extractable)
    throw new Error("toPEM requires an extractable key");

  const label =
        (key.type == "private") ? " PRIVATE " :
        (key.type == "public") ? " PUBLIC " :
        " ";

  const format =
        (key.type == "private") ? "pkcs8" :
        (key.type == "public") ? "spki" :
        "raw";

  const exported = await window.crypto.subtle.exportKey(format, key);
  let b64key = window.btoa(ab2str(exported));

  let pem = `-----BEGIN${label}KEY-----\n`;
  while (b64key.length > 0) {
    pem += b64key.substring(0, 76) + '\n';
    b64key = b64key.substring(64);
  }
  pem += `-----END${label}KEY-----`;

  return pem;
}
