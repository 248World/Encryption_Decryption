
const express = require("express");
const { pool, testDatabaseConnection } = require("../../db");
const { hashPassword } = require("./passwords");
const { createRegistrationService } = require("./registration");
const {
  createEmailVerificationService,
} = require("./email-verification");
const {
  createDefaultEmailService,
} = require("./email");

const defaultEmailService = createDefaultEmailService();

const defaultRegistrationService = createRegistrationService({
  pool,
  hashPassword,
  sendVerificationEmail: ({ to, token }) =>
    defaultEmailService.sendVerificationEmail({ to, token }),
});

const defaultEmailVerificationService =
  createEmailVerificationService({
    pool,
  });

function createSecureShareRouter(
  databaseCheck = testDatabaseConnection,
  registrationService = defaultRegistrationService,
  emailVerificationService = defaultEmailVerificationService
) {
  const router = express.Router();

  // SecureShare API and database health check.
  router.get("/health", async (_req, res) => {
    try {
      await databaseCheck();

      return res.status(200).json({
        service: "CipherNest SecureShare",
        status: "ok",
        database: "connected",
      });
    } catch (_error) {
      return res.status(503).json({
        service: "CipherNest SecureShare",
        status: "unavailable",
        database: "disconnected",
      });
    }
  });

  // Register a business owner and create their workspace.
  router.post("/auth/register", async (req, res) => {
    try {
      const result = await registrationService(req.body);

      return res.status(201).json({
        message: result.verificationEmailSent
          ? "Registration successful. Please check your email to verify your account."
          : "Registration successful, but the verification email could not be sent. Please try again later.",
        account: result,
      });
    } catch (error) {
      if (error instanceof TypeError) {
        return res.status(400).json({
          error: error.message,
        });
      }

      if (error.code === "ER_DUP_ENTRY") {
        return res.status(409).json({
          error: "An account with this email address already exists.",
        });
      }

      return res.status(500).json({
        error:
          "Registration could not be completed. Please try again later.",
      });
    }
  });

  // Verify an account's email address.
  router.post("/auth/verify-email", async (req, res) => {
    try {
      const { token } = req.body || {};

      const verified = await emailVerificationService(token);

      if (!verified) {
        return res.status(400).json({
          error: "The verification link is invalid or has expired.",
        });
      }

      return res.status(200).json({
        message: "Email address verified successfully.",
      });
    } catch (_error) {
      return res.status(500).json({
        error:
          "Email verification could not be completed. Please try again later.",
      });
    }
  });

  return router;
}

module.exports = createSecureShareRouter();
module.exports.createSecureShareRouter = createSecureShareRouter;
