const {
  hashVerificationToken,
} = require("./verification-tokens");

function createEmailVerificationService({
  pool,
  hashToken = hashVerificationToken,
}) {
  if (!pool || typeof pool.getConnection !== "function") {
    throw new TypeError("A valid database pool is required.");
  }

  if (typeof hashToken !== "function") {
    throw new TypeError("A token hashing function is required.");
  }

  return async function verifyEmail(token) {
    if (
      typeof token !== "string" ||
      !/^[a-f0-9]{64}$/i.test(token)
    ) {
      return false;
    }

    const tokenHash = hashToken(token);
    const connection = await pool.getConnection();

    let transactionStarted = false;

    try {
      await connection.beginTransaction();
      transactionStarted = true;

      // Lock the token record to prevent concurrent reuse.
      const [rows] = await connection.execute(
        `SELECT id, user_id
         FROM email_verification_tokens
         WHERE token_hash = ?
           AND used_at IS NULL
           AND expires_at > CURRENT_TIMESTAMP
         LIMIT 1
         FOR UPDATE`,
        [tokenHash]
      );

      if (rows.length === 0) {
        await connection.commit();
        transactionStarted = false;
        return false;
      }

      const verificationRecord = rows[0];

      // Mark the user's email as verified.
      await connection.execute(
        `UPDATE users
         SET email_verified_at = COALESCE(
           email_verified_at,
           CURRENT_TIMESTAMP
         )
         WHERE id = ?`,
        [verificationRecord.user_id]
      );

      // Consume the token so it cannot be reused.
      await connection.execute(
        `UPDATE email_verification_tokens
         SET used_at = CURRENT_TIMESTAMP
         WHERE id = ?
           AND used_at IS NULL`,
        [verificationRecord.id]
      );

      await connection.commit();
      transactionStarted = false;

      return true;
    } catch (error) {
      if (transactionStarted) {
        try {
          await connection.rollback();
        } catch (_rollbackError) {
          // Preserve the original error.
        }
      }

      throw error;
    } finally {
      connection.release();
    }
  };
}

module.exports = {
  createEmailVerificationService,
};