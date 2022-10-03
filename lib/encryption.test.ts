import Encryption from "./encryption";

test("encryption work as expected", () => {
  const enc = new Encryption();
  const plaintext = "hello, world";
  const { cipher, iv } = enc.encrypt(plaintext);
  const dec_result = enc.decrypt(cipher, iv);
  expect(dec_result).toBe(plaintext);
});
