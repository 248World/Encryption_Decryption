
const express = require("express");

const app = express();

// Reduce unnecessary framework and response fingerprinting.
app.disable("x-powered-by");
app.disable("etag");

// Apply security headers to every backend response.
app.use((_req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });

  next();
});

// Health check for deployment monitoring.
app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// Generic response for all other routes.
// Encryption and decryption are performed in the browser.
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Local development server.
if (require.main === module) {
  const PORT = process.env.PORT || 5000;

  app.listen(PORT, () => {
    console.log(`Health service running on port ${PORT}`);
  });
}

module.exports = app;
