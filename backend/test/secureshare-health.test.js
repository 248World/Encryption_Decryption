const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");

const {
  createSecureShareRouter,
} = require("../api/secureshare");

async function startTestServer(databaseCheck) {
  const app = express();

  app.use(
    "/api/secureshare",
    createSecureShareRouter(databaseCheck)
  );

  const server = http.createServer(app);

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  return {
    server,
    baseUrl: `http://127.0.0.1:${server.address().port}`,
  };
}

test("SecureShare health returns 200 when the database is connected", async (t) => {
  const { server, baseUrl } = await startTestServer(
    async () => true
  );

  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (
      error ? reject(error) : resolve()
    ));
  }));

  const response = await fetch(
    `${baseUrl}/api/secureshare/health`
  );

  assert.equal(response.status, 200);

  assert.deepEqual(await response.json(), {
    service: "CipherNest SecureShare",
    status: "ok",
    database: "connected",
  });
});

test("SecureShare health returns 503 when the database is unavailable", async (t) => {
  const { server, baseUrl } = await startTestServer(
    async () => {
      throw new Error("Simulated database failure");
    }
  );

  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (
      error ? reject(error) : resolve()
    ));
  }));

  const response = await fetch(
    `${baseUrl}/api/secureshare/health`
  );

  assert.equal(response.status, 503);

  assert.deepEqual(await response.json(), {
    service: "CipherNest SecureShare",
    status: "unavailable",
    database: "disconnected",
  });
});