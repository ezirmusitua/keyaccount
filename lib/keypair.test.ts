import KeyPair from "./keypair";
import { randomBytes } from "./utils";

test("KeyPair work as expected", async () => {
  const keypair = await KeyPair.generate();
  const plaintext = randomBytes(16);
  const ciphertext = keypair.encrypt(plaintext);
  const dec_result = keypair.decrypt(ciphertext);
  expect(dec_result).toBe(plaintext);
});
