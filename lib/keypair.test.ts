import KeyPair from "./keypair";
import { randomBytes, bytesToHex } from "./utils";
import * as crypto from "crypto";

test("KeyPair work as expected", async () => {
  const keypair = await KeyPair.generate();
  const plaintext = randomBytes(16);
  const ciphertext = keypair.encrypt(plaintext);
  const dec_result = keypair.decrypt(ciphertext);
  expect(dec_result).toBe(plaintext);
});

test("KeyPair work with Buffer with hex encoding", async () => {
  const keypair = await KeyPair.generate();
  const plaintext = crypto.randomBytes(16);
  const ciphertext = keypair.encrypt(plaintext.toString("hex"));
  const dec_result = keypair.decrypt(ciphertext);
  expect(dec_result).toBe(plaintext.toString("hex"));
});
