import Encryption from "./encryption";
import { iKeyStore } from "./interface";
import KeyPair from "./keypair";
import {
  bytesToHex,
  hexToBytes,
  pbkdf2,
  privateKeyFromPem,
  publicKeyFromPem,
  randomBytes,
} from "./utils";

export const ITER_NUM = 12;
export const KEY_SIZE = 32;

class Account {
  private _keyPair: KeyPair = null as any;

  constructor(private readonly _keyStore: iKeyStore) {}

  get keyStore() {
    return this._keyStore;
  }

  get locked() {
    return !this._keyPair;
  }

  lock() {
    this._keyPair = null as any;
  }

  async unlock(password: string) {
    const key = await Account.derive_key(
      password,
      hexToBytes(this._keyStore.salt),
      this._keyStore.iter_num,
      this._keyStore.key_size
    );
    const enc = new Encryption(key);
    const plain = enc.decrypt(this._keyStore.private_key, this._keyStore.iv);
    const private_key = privateKeyFromPem(plain);
    const public_key = publicKeyFromPem(this._keyStore.public_key);
    this._keyPair = new KeyPair(public_key, private_key);
  }

  encrypt(data: string) {
    const enc = new Encryption();
    const { cipher, iv } = enc.encrypt(data);
    const encrypted_key = this._keyPair.encrypt(enc.key);
    return {
      cipher,
      iv,
      key: encrypted_key,
    };
  }

  decrypt({ cipher, iv, key }: any) {
    const _key = this._keyPair.decrypt(key);
    const enc = new Encryption(_key);
    const plain = enc.decrypt(cipher, iv);
    return plain;
  }

  static async derive_key(
    password: string,
    salt: string,
    iter_num = ITER_NUM,
    key_size = KEY_SIZE
  ) {
    return (await new Promise((resolve, reject) =>
      pbkdf2(password, salt, iter_num, key_size, (err, key) => {
        if (err || !key) return reject("");
        return resolve(key);
      })
    )) as string;
  }

  static async generate(password: string) {
    const salt = randomBytes(16);
    const key = await Account.derive_key(password, salt);
    const keyPair = await KeyPair.generate();
    const enc = new Encryption(key);
    const { cipher, iv } = enc.encrypt(keyPair.prv_pem);
    return new Account({
      key_size: KEY_SIZE,
      public_key: keyPair.pub_pem,
      salt: bytesToHex(salt),
      iter_num: ITER_NUM,
      private_key: cipher,
      iv,
    });
  }
}

export default Account;
