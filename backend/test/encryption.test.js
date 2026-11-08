
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const {
  encryptWithPassword,
  decryptWithPassword,
} = require("../test-support/crypto");

const app = require("../server");

test("AES-256-GCM encrypts and decrypts text", async () => {
  const original = "Hello! This is a private message. \u0645\u0631\u062d\u0628\u0627";
  const encrypted = await encryptWithPassword(
    original,
    "a-strong-demo-password"
  );

  assert.match(encrypted, /^AES256GCM:v1:/);

  assert.equal(
    await decryptWithPassword(encrypted, "a-strong-demo-password"),
    original
  );
});

test("each encryption uses a fresh salt and IV", async () => {
  const first = await encryptWithPassword("same text", "same password");
  const second = await encryptWithPassword("same text", "same password");

  assert.notEqual(first, second);
});

test("wrong password is rejected", async () => {
  const encrypted = await encryptWithPassword(
    "secret",
    "correct-password"
  );

  await assert.rejects(
    () => decryptWithPassword(encrypted, "incorrect-password")
  );
});

test("modified encrypted data is rejected", async () => {
  const encrypted = await encryptWithPassword(
    "secret",
    "correct-password"
  );

  const changed = encrypted.slice(0, -2) + "AA";

  await assert.rejects(
    () => decryptWithPassword(changed, "correct-password")
  );
});

test("health endpoint works and retired encryption APIs are unavailable", async (t) => {
  const server = http.createServer(app);

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));

  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const health = await fetch(`${baseUrl}/health`);

  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.equal(health.headers.get("x-powered-by"), null);

  for (const route of ["/api/encrypt", "/api/decrypt"]) {
    const response = await fetch(`${baseUrl}${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "private message",
        key: "example-password",
      }),
    });

    assert.equal(response.status, 404, `${route} should return 404`);
    assert.deepEqual(await response.json(), { error: "Not found" });
  }
});
