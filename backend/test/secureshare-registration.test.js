
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

test("registration creates a user, business, and owner membership in one transaction", async () => {
  const database = createFakeDatabase();

  const ids = [
    "user-id",
    "business-id",
    "membership-id",
  ];

  let idIndex = 0;

  const registerBusinessOwner = createRegistrationService({
    pool: database.pool,
    hashPassword: async () => "fake-argon2-hash",
    createId: () => ids[idIndex++],
  });

  const result = await registerBusinessOwner(validInput);

  assert.deepEqual(result, {
    userId: "user-id",
    businessId: "business-id",
    email: "owner@example.com",
    emailVerified: false,
    emailVerificationRequired: true,
  });

  assert.equal(database.state.queries.length, 4);
  assert.equal(database.state.committed, true);
  assert.equal(database.state.rolledBack, false);
  assert.equal(database.state.released, true);

  assert.match(database.state.queries[1].sql, /INSERT INTO users/);
  assert.match(database.state.queries[2].sql, /INSERT INTO businesses/);
  assert.match(database.state.queries[3].sql, /INSERT INTO memberships/);

  assert.equal(database.state.queries[3].values[2], "user-id");
});

test("registration rolls back when a database operation fails", async () => {
  const database = createFakeDatabase(2);

  const registerBusinessOwner = createRegistrationService({
    pool: database.pool,
    hashPassword: async () => "fake-argon2-hash",
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
