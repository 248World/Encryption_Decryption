
const { randomUUID } = require("node:crypto");

const {
  createVerificationToken,
  VERIFICATION_TOKEN_EXPIRY_HOURS,
} = require("./verification-tokens");

function validateRegistrationInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Invalid registration details.");
  }

  const { fullName, email, password, businessName } = input;

  if (
    typeof fullName !== "string" ||
    !fullName.trim() ||
    fullName.trim().length > 150
  ) {
    throw new TypeError("Full name must contain between 1 and 150 characters.");
  }

  if (typeof email !== "string") {
    throw new TypeError("A valid email address is required.");
  }

  const normalizedEmail = email.trim().toLowerCase();

  if (
    normalizedEmail.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  ) {
    throw new TypeError("A valid email address is required.");
  }

  if (
    typeof password !== "string" ||
    Array.from(password).length < 12 ||
    Buffer.byteLength(password, "utf8") > 1024
  ) {
    throw new TypeError(
      "Password must contain at least 12 characters and no more than 1024 UTF-8 bytes."
    );
  }

  if (
    typeof businessName !== "string" ||
    !businessName.trim() ||
    businessName.trim().length > 200
  ) {
    throw new TypeError("Business name must contain between 1 and 200 characters.");
  }

  return {
    fullName: fullName.trim(),
    email: normalizedEmail,
    password,
    businessName: businessName.trim(),
  };
}

function createRegistrationService({
  pool,
  hashPassword,
  createId = randomUUID,
  generateVerificationToken = createVerificationToken,
  sendVerificationEmail = async () => {
    throw new Error("Email delivery is not configured.");
  },
}) {
  if (!pool || typeof pool.getConnection !== "function") {
    throw new TypeError("A valid database pool is required.");
  }

  if (typeof hashPassword !== "function") {
    throw new TypeError("A password hashing function is required.");
  }

  if (typeof generateVerificationToken !== "function") {
    throw new TypeError("A verification token generator is required.");
  }

  if (typeof sendVerificationEmail !== "function") {
    throw new TypeError("An email delivery function is required.");
  }

  return async function registerBusinessOwner(input) {
    const details = validateRegistrationInput(input);

    const passwordHash = await hashPassword(details.password);

    const verification = generateVerificationToken();

    if (
      !verification ||
      typeof verification.token !== "string" ||
      !/^[a-f0-9]{64}$/i.test(verification.token) ||
      typeof verification.tokenHash !== "string" ||
      !/^[a-f0-9]{64}$/i.test(verification.tokenHash)
    ) {
      throw new TypeError("Invalid verification token data.");
    }

    const userId = createId();
    const businessId = createId();
    const membershipId = createId();
    const verificationTokenId = createId();

    const expiresAt = new Date(
      Date.now() + VERIFICATION_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000
    );

    const expiresAtSql = expiresAt
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    const connection = await pool.getConnection();

    let transactionStarted = false;

    try {
      await connection.beginTransaction();
      transactionStarted = true;

      await connection.execute(
        `INSERT INTO users
          (id, email, password_hash, full_name)
         VALUES (?, ?, ?, ?)`,
        [
          userId,
          details.email,
          passwordHash,
          details.fullName,
        ]
      );

      await connection.execute(
        `INSERT INTO businesses
          (id, name, created_by)
         VALUES (?, ?, ?)`,
        [
          businessId,
          details.businessName,
          userId,
        ]
      );

      await connection.execute(
        `INSERT INTO memberships
          (id, business_id, user_id, role)
         VALUES (?, ?, ?, 'owner')`,
        [
          membershipId,
          businessId,
          userId,
        ]
      );

      await connection.execute(
        `INSERT INTO email_verification_tokens
          (id, user_id, token_hash, expires_at)
         VALUES (?, ?, ?, ?)`,
        [
          verificationTokenId,
          userId,
          verification.tokenHash,
          expiresAtSql,
        ]
      );

      await connection.commit();
      transactionStarted = false;
    } catch (error) {
      if (transactionStarted) {
        try {
          await connection.rollback();
        } catch (_rollbackError) {
          // Preserve the original database error.
        }
      }

      throw error;
    } finally {
      connection.release();
    }

    // Send the raw token only after the database transaction commits.
    // Never return the raw token to the API caller.
    let emailSent = false;

    try {
      await sendVerificationEmail({
        to: details.email,
        token: verification.token,
      });

      emailSent = true;
    } catch (_emailError) {
      // Registration remains successful.
      // A resend-verification feature will handle delivery failures.
    }

    return {
      userId,
      businessId,
      email: details.email,
      emailVerified: false,
      emailVerificationRequired: true,
      verificationEmailSent: emailSent,
    };
  };
}

module.exports = {
  createRegistrationService,
  validateRegistrationInput,
};
