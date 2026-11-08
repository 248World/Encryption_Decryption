
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const backendCrypto = require("../test-support/crypto");

const browserSource = fs.readFileSync(
  path.join(__dirname, "../../frontend/crypto.js"),
  "utf8"
);

function loadBrowserCrypto() {
  const sandbox = {
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    btoa,
    atob,
  };

  sandbox.window = sandbox;

  vm.runInNewContext(browserSource, sandbox);

  return sandbox.TextCrypto;
}

const browser = loadBrowserCrypto();

const password = "Compatibility-Test-Password-2026!";
const message = "Hello! Browser compatibility test. Encryption 🔐 العربية";

test("browser encrypts text that the independent test implementation can decrypt", async () => {
  const encrypted = await browser.encryptText(message, password);

  assert.ok(encrypted.startsWith("AES256GCM:v1:"));

  const decrypted = await backendCrypto.decryptWithPassword(
    encrypted,
    password
  );

  assert.equal(decrypted, message);
});

test("independent test implementation encrypts text that browser can decrypt", async () => {
  const encrypted = await backendCrypto.encryptWithPassword(
    message,
    password
  );

  const decrypted = await browser.decryptText(encrypted, password);

  assert.equal(decrypted, message);
});

test("browser rejects an incorrect password", async () => {
  const encrypted = await browser.encryptText(message, password);

  await assert.rejects(
    () => browser.decryptText(encrypted, "Wrong-Password"),
    /Wrong password or encrypted data has been modified/
  );
});

test("browser rejects modified ciphertext", async () => {
  const encrypted = await browser.encryptText(message, password);

  const prefix = "AES256GCM:v1:";
  const payload = encrypted.slice(prefix.length);

  const envelope = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );

  const ciphertext = Buffer.from(envelope.ciphertext, "base64");

  ciphertext[0] ^= 1;

  envelope.ciphertext = ciphertext.toString("base64");

  const modified =
    prefix +
    Buffer.from(JSON.stringify(envelope)).toString("base64url");

  await assert.rejects(
    () => browser.decryptText(modified, password)
  );
});
