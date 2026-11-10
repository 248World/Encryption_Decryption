
const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const { createServer } = require("node:http");

const {
  createSecureShareRouter,
} = require("../api/secureshare");

async function startTestServer(registrationService) {
  const app = express();

  app.use(express.json());

  app.use(
    "/api/secureshare",
    createSecureShareRouter(
      async () => true,
      registrationService
    )
  );

  const server = createServer(app);

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

const validInput = {
  fullName: "Test Owner",
  email: "owner@example.com",
  password: "CipherNest-Test-123!",
  businessName: "Test Company",
};

test("registration API returns 201 when registration and email delivery succeed", async () => {
  const server = await startTestServer(async () => ({
    userId: "user-id",
    businessId: "business-id",
    email: "owner@example.com",
    emailVerified: false,
    emailVerificationRequired: true,
    verificationEmailSent: true,
  }));

  try {
    const response = await fetch(
      `${server.baseUrl}/api/secureshare/auth/register`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(validInput),
      }
    );

    const body = await response.json();

    assert.equal(response.status, 201);
    assert.equal(body.account.userId, "user-id");
    assert.equal(body.account.emailVerified, false);
    assert.equal(body.account.verificationEmailSent, true);
    assert.match(
      body.message,
      /Please check your email to verify your account/
    );
  } finally {
    await server.close();
  }
});

test("registration API reports when verification email delivery fails", async () => {
  const server = await startTestServer(async () => ({
    userId: "user-id",
    businessId: "business-id",
    email: "owner@example.com",
    emailVerified: false,
    emailVerificationRequired: true,
    verificationEmailSent: false,
  }));

  try {
    const response = await fetch(
      `${server.baseUrl}/api/secureshare/auth/register`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(validInput),
      }
    );

    const body = await response.json();

    assert.equal(response.status, 201);
    assert.equal(body.account.verificationEmailSent, false);
    assert.match(
      body.message,
      /verification email could not be sent/
    );
  } finally {
    await server.close();
  }
});

test("registration API returns 400 for invalid input", async () => {
  const server = await startTestServer(async () => {
    throw new TypeError("A valid email address is required.");
  });

  try {
    const response = await fetch(
      `${server.baseUrl}/api/secureshare/auth/register`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(validInput),
      }
    );

    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, "A valid email address is required.");
  } finally {
    await server.close();
  }
});

test("registration API returns 409 for an existing email", async () => {
  const server = await startTestServer(async () => {
    const error = new Error("Duplicate entry");
    error.code = "ER_DUP_ENTRY";
    throw error;
  });

  try {
    const response = await fetch(
      `${server.baseUrl}/api/secureshare/auth/register`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(validInput),
      }
    );

    const body = await response.json();

    assert.equal(response.status, 409);
    assert.match(body.error, /already exists/);
  } finally {
    await server.close();
  }
});

test("registration API returns a generic 500 for unexpected errors", async () => {
  const server = await startTestServer(async () => {
    throw new Error("Internal database details");
  });

  try {
    const response = await fetch(
      `${server.baseUrl}/api/secureshare/auth/register`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(validInput),
      }
    );

    const body = await response.json();

    assert.equal(response.status, 500);
    assert.equal(
      body.error,
      "Registration could not be completed. Please try again later."
    );
    assert.doesNotMatch(
      JSON.stringify(body),
      /Internal database details/
    );
  } finally {
    await server.close();
  }
});
