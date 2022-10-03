import { ASYM_ENC_SCHEME, KEYPAIR_BITS, KEYPAIR_WORKERS } from "./constant";
import { tRsaPubKey, tRsaPrvKey, tRsaKeyPair } from "./interface";
import {
  bytesToHex,
  generateRsaKeyPair,
  hexToBytes,
  privateKeyToPem,
  publicKeyToPem,
} from "./utils";

class KeyPair {
  constructor(
    private readonly pub_key: tRsaPubKey,
    private readonly prv_key: tRsaPrvKey
  ) {}

  get pub_pem() {
    return publicKeyToPem(this.pub_key);
  }

  get prv_pem() {
    return privateKeyToPem(this.prv_key);
  }

  encrypt(plain: string) {
    return bytesToHex(this.pub_key.encrypt(plain, ASYM_ENC_SCHEME));
  }

  decrypt(cipher: string) {
    return this.prv_key.decrypt(hexToBytes(cipher), ASYM_ENC_SCHEME);
  }

  static async generate(): Promise<KeyPair> {
    return new Promise((resolve) =>
      generateRsaKeyPair(
        { bits: KEYPAIR_BITS, workers: KEYPAIR_WORKERS },
        (_, keypair: tRsaKeyPair) => {
          resolve(new KeyPair(keypair.publicKey, keypair.privateKey));
        }
      )
    );
  }
}

export default KeyPair;
