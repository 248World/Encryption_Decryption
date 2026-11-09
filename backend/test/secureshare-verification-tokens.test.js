const test = require("node:test");
const assert = require("node:assert/strict");

const {
  createVerificationToken,
  hashVerificationToken,
  VERIFICATION_TOKEN_EXPIRY_HOURS,
} = require("../api/secureshare/verification-tokens");

test("verification token is cryptographically random and 64 hex characters", () => {
  const first = createVerificationToken();
  const second = createVerificationToken();

  assert.match(first.token, /^[a-f0-9]{64}$/);
  assert.match(second.token, /^[a-f0-9]{64}$/);
  assert.notEqual(first.token, second.token);
});

test("verification token hash is SHA-256 and does not equal the raw token", () => {
  const result = createVerificationToken();

  assert.match(result.tokenHash, /^[a-f0-9]{64}$/);
  assert.notEqual(result.tokenHash, result.token);
  assert.equal(hashVerificationToken(result.token), result.tokenHash);
});

test("verification tokens expire after 24 hours", () => {
  const result = createVerificationToken();

  assert.equal(VERIFICATION_TOKEN_EXPIRY_HOURS, 24);
  assert.equal(result.expiresInHours, 24);
});

test("hashVerificationToken rejects invalid tokens", () => {
  assert.throws(
    () => hashVerificationToken("invalid-token"),
    /Invalid verification token/
  );
});