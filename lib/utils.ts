import * as forge from "node-forge";

export const bytesToHex = forge.util.bytesToHex;
export const hexToBytes = forge.util.hexToBytes;
export const bufferToBytes = (b: Buffer) =>
  forge.util.createBuffer(b.toString("binary"));

export const generateRsaKeyPair = forge.pki.rsa.generateKeyPair;
export const privateKeyFromPem = forge.pki.privateKeyFromPem;
export const privateKeyToPem = forge.pki.privateKeyToPem;
export const publicKeyFromPem = forge.pki.publicKeyFromPem;
export const publicKeyToPem = forge.pki.publicKeyToPem;

export const randomBytes = forge.random.getBytesSync;
export const pbkdf2 = forge.pkcs5.pbkdf2;

export const toBuffer = forge.util.createBuffer;
export const toByteStringBuffer = forge.util.ByteStringBuffer;

export const createCipher = forge.cipher.createCipher;
export const createDecipher = forge.cipher.createDecipher;
