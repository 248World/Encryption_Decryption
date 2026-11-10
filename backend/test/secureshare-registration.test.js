
const test = require("node:test");
const assert = require("node:assert/strict");

const {
  createRegistrationService,
} = require("../api/secureshare/registration");

const validInput = {
  fullName: "Test Owner",
  email: "OWNER@EXAMPLE.COM",
  password: "CipherNest-Test-123!",
  businessName: "Test Company",
};

const fakeToken = {
  token: "a".repeat(64),
  tokenHash: "b".repeat(64),
  expiresInHours: 24,
};

function createFakeDatabase(failAt = null) {
  const state = {
    queries: [],
    committed: false,
    rolledBack: false,
    released: false,
  };

  const connection = {
    async beginTransaction() {
      state.queries.push("BEGIN");

      if (failAt === "begin") {
        throw new Error("Simulated transaction failure");
      }
    },

    async execute(sql, values) {
      state.queries.push({ sql, values });

      if (failAt === state.queries.length - 1) {
        throw new Error("Simulated database failure");
      }
    },

    async commit() {
      state.committed = true;
    },

    async rollback() {
      state.rolledBack = true;
    },

    release() {
      state.released = true;
    },
  };

  return {
    state,
    pool: {
      async getConnection() {
        return connection;
      },
    },
  };
}

test("registration creates a user, business, membership, and verification token in one transaction", async () => {
  const database = createFakeDatabase();

  const ids = [
    "user-id",
    "business-id",
    "membership-id",
    "verification-token-id",
  ];

  let idIndex = 0;
  const sentEmails = [];

  const registerBusinessOwner = createRegistrationService({
    pool: database.pool,
    hashPassword: async () => "fake-argon2-hash",
    createId: () => ids[idIndex++],
    generateVerificationToken: () => fakeToken,
    sendVerificationEmail: async (details) => {
      sentEmails.push(details);
    },
  });

  const result = await registerBusinessOwner(validInput);

  assert.deepEqual(result, {
    userId: "user-id",
    businessId: "business-id",
    email: "owner@example.com",
    emailVerified: false,
    emailVerificationRequired: true,
    verificationEmailSent: true,
  });

  // Verify that the email was sent with the raw token.
  assert.equal(sentEmails.length, 1);
  assert.equal(sentEmails[0].to, "owner@example.com");
  assert.equal(sentEmails[0].token, fakeToken.token);

  // Verify that the database transaction completed successfully.
  assert.equal(database.state.queries.length, 5);
  assert.equal(database.state.committed, true);
  assert.equal(database.state.rolledBack, false);
  assert.equal(database.state.released, true);

  assert.match(database.state.queries[1].sql, /INSERT INTO users/);
  assert.match(database.state.queries[2].sql, /INSERT INTO businesses/);
  assert.match(database.state.queries[3].sql, /INSERT INTO memberships/);
  assert.match(
    database.state.queries[4].sql,
    /INSERT INTO email_verification_tokens/
  );

  assert.equal(database.state.queries[3].values[2], "user-id");

  const tokenInsert = database.state.queries[4];

  assert.deepEqual(tokenInsert.values.slice(0, 3), [
    "verification-token-id",
    "user-id",
    fakeToken.tokenHash,
  ]);

  assert.match(
    tokenInsert.values[3],
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/
  );

  // The raw token must never appear in the public result.
  assert.equal(
    JSON.stringify(result).includes(fakeToken.token),
    false
  );

  // Only the token hash should be stored in the database.
  assert.equal(
    JSON.stringify(database.state.queries).includes(fakeToken.token),
    false
  );
});

test("registration rolls back when a database operation fails", async () => {
  const database = createFakeDatabase(2);

  const registerBusinessOwner = createRegistrationService({
    pool: database.pool,
    hashPassword: async () => "fake-argon2-hash",
    generateVerificationToken: () => fakeToken,
  });

  await assert.rejects(
    registerBusinessOwner(validInput),
    /Simulated database failure/
  );

  assert.equal(database.state.committed, false);
  assert.equal(database.state.rolledBack, true);
  assert.equal(database.state.released, true);
});

test("registration rolls back when verification token storage fails", async () => {
  const database = createFakeDatabase(4);

  const registerBusinessOwner = createRegistrationService({
    pool: database.pool,
    hashPassword: async () => "fake-argon2-hash",
    generateVerificationToken: () => fakeToken,
  });

  await assert.rejects(
    registerBusinessOwner(validInput),
    /Simulated database failure/
  );

  assert.equal(database.state.committed, false);
  assert.equal(database.state.rolledBack, true);
  assert.equal(database.state.released, true);
});

test("registration does not open a database connection for invalid input", async () => {
  let connectionRequested = false;

  const registerBusinessOwner = createRegistrationService({
    pool: {
      async getConnection() {
        connectionRequested = true;
        throw new Error("Database should not be reached");
      },
    },
    hashPassword: async () => "fake-argon2-hash",
  });

  await assert.rejects(
    registerBusinessOwner({
      ...validInput,
      password: "short",
    }),
    /at least 12 characters/
  );

  assert.equal(connectionRequested, false);
});
