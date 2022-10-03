import { SYM_ENC_ALG, SYM_IV_SIZE, SYM_KEY_SIZE } from "./constant";
import { tHex } from "./interface";
import {
  bytesToHex,
  createCipher,
  createDecipher,
  hexToBytes,
  randomBytes,
  toBuffer,
  toByteStringBuffer,
} from "./utils";

class Encryption {
  private _key = "";

  constructor(_key = "") {
    this._key = _key || randomBytes(SYM_KEY_SIZE);
  }

  get key() {
    return this._key;
  }

  encrypt(plain: string) {
    const iv = randomBytes(SYM_IV_SIZE);
    const cipher = createCipher(SYM_ENC_ALG, this._key);
    cipher.start({ iv });
    cipher.update(toBuffer(plain));
    cipher.finish();
    return {
      cipher: cipher.output.toHex(),
      iv: bytesToHex(iv),
    };
  }

  decrypt(_cipher: tHex, _iv: tHex) {
    const iv = toBuffer(hexToBytes(_iv));
    const cipher = new toByteStringBuffer(hexToBytes(_cipher));
    const decipher = createDecipher(SYM_ENC_ALG, this._key);
    decipher.start({ iv });
    decipher.update(cipher);
    const result = decipher.finish();
    if (!result) throw new Error("Decryption failed");
    const plain = decipher.output.toString();
    return plain;
  }
}

export default Encryption;
