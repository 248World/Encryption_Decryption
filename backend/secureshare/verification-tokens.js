const {
  randomBytes,
  createHash,
} = require("node:crypto");

const VERIFICATION_TOKEN_EXPIRY_HOURS = 24;
const VERIFICATION_TOKEN_BYTES = 32;

function createVerificationToken() {
  const token = randomBytes(VERIFICATION_TOKEN_BYTES).toString("hex");

  const tokenHash = createHash("sha256")
    .update(token, "utf8")
    .digest("hex");

  return {
    token,
    tokenHash,
    expiresInHours: VERIFICATION_TOKEN_EXPIRY_HOURS,
  };
}

function hashVerificationToken(token) {
  if (typeof token !== "string" || !/^[a-f0-9]{64}$/i.test(token)) {
    throw new TypeError("Invalid verification token.");
  }

  return createHash("sha256")
    .update(token, "utf8")
    .digest("hex");
}

module.exports = {
  createVerificationToken,
  hashVerificationToken,
  VERIFICATION_TOKEN_EXPIRY_HOURS,
};