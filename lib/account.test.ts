import Account from "./account";
import { randomBytes } from "./utils";

test("Account work as expected", async () => {
  const password = randomBytes(16);
  const account = await Account.generate(password);
  account.lock();
  expect(account.locked).toBe(true);
  await account.unlock(password);
  expect(account.locked).toBe(false);
  const plaintext = "Hello, World";
  const { cipher, iv, key } = account.encrypt(plaintext);
  const dec_result = account.decrypt({ cipher, iv, key });
  expect(dec_result).toBe(plaintext);
});
