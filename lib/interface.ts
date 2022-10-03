import * as forge from "node-forge";

export interface iEncRes {
  cipher: tHex;
  iv: tHex;
}

export interface iEncMat {
  password: string;
  salt: string;
  key: string;
  iter_num: number;
  key_size: number;
}

export interface iKeyStore {
  salt: tHex;
  iter_num: number;
  key_size: number;
  iv: tHex;
  private_key: tHex;
  public_key: tHex;
}

export interface iDecRes {
  plain: string;
  success: boolean;
}

export type tHex = string;

export type tRsaKeyPair = forge.pki.rsa.KeyPair;

export type tRsaPubKey = forge.pki.rsa.PublicKey;

export type tRsaPrvKey = forge.pki.rsa.PrivateKey;
