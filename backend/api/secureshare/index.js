const express = require("express");
const { testDatabaseConnection } = require("../../db");

function createSecureShareRouter(
  databaseCheck = testDatabaseConnection
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

  return router;
}

module.exports = createSecureShareRouter();
module.exports.createSecureShareRouter = createSecureShareRouter;