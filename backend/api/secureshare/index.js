
const express = require("express");
const { pool, testDatabaseConnection } = require("../../db");
const { hashPassword } = require("./passwords");
const { createRegistrationService } = require("./registration");

const defaultRegistrationService = createRegistrationService({
  pool,
  hashPassword,
});

function createSecureShareRouter(
  databaseCheck = testDatabaseConnection,
  registrationService = defaultRegistrationService
) {
  const router = express.Router();

  // SecureShare API and database health check.
  router.get("/health", async (_req, res) => {
    try {
      await databaseCheck();

      res.status(200).json({
        service: "CipherNest SecureShare",
        status: "ok",
        database: "connected",
      });
    } catch (_error) {
      res.status(503).json({
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
        message:
          "Registration successful. Email verification is required before workspace access.",
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

  return router;
}

module.exports = createSecureShareRouter();
module.exports.createSecureShareRouter = createSecureShareRouter;
