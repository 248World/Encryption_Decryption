
const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const pbkdf2 = promisify(crypto.pbkdf2);
const app = express();

app.use(express.json({ limit: "1mb" }));

const allowedOrigins = [
  "https://encryptiondecryption-frontend.vercel.app",
  "http://localhost:3000",
];

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
  })
);

const FORMAT_PREFIX = "AES256GCM:v1:";
const PBKDF2_ITERATIONS = 600000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// AES-256-GCM encryption
async function encryptWithPassword(plainText, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  const key = await pbkdf2(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    "sha256"
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const ciphertext = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final(),
  ]);

  const envelope = {
    version: 1,
    kdf: "pbkdf2-sha256",
    iterations: PBKDF2_ITERATIONS,
    cipher: "aes-256-gcm",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };

  return (
    FORMAT_PREFIX +
    Buffer.from(JSON.stringify(envelope)).toString("base64url")
  );
}

// AES-256-GCM decryption
async function decryptWithPassword(payload, password) {
  // Accept uppercase or lowercase prefix.
  // Do not change the case of the encrypted payload.
  if (
    typeof payload !== "string" ||
    payload.slice(0, FORMAT_PREFIX.length).toLowerCase() !==
      FORMAT_PREFIX.toLowerCase()
  ) {
    throw new Error("Unsupported encrypted format");
  }

  let envelope;

  try {
    const encoded = payload.slice(FORMAT_PREFIX.length);

    envelope = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );
  } catch {
    throw new Error("Invalid encrypted data");
  }

  if (
    envelope.version !== 1 ||
    envelope.kdf !== "pbkdf2-sha256" ||
    envelope.cipher !== "aes-256-gcm" ||
    envelope.iterations !== PBKDF2_ITERATIONS
  ) {
    throw new Error("Unsupported encrypted data version");
  }

  const salt = Buffer.from(envelope.salt || "", "base64");
  const iv = Buffer.from(envelope.iv || "", "base64");
  const authTag = Buffer.from(envelope.authTag || "", "base64");
  const ciphertext = Buffer.from(envelope.ciphertext || "", "base64");

  if (
    salt.length !== SALT_LENGTH ||
    iv.length !== IV_LENGTH ||
    authTag.length !== AUTH_TAG_LENGTH
  ) {
    throw new Error("Invalid encrypted data");
  }

  const key = await pbkdf2(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    "sha256"
  );

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}

// Validate text and password
function validateTextAndPassword(text, password) {
  return (
    typeof text === "string" &&
    typeof password === "string" &&
    text.length <= 500000 &&
    password.length > 0 &&
    password.length <= 1024
  );
}

// Encryption API
app.post("/api/encrypt", async (req, res) => {
  const { text, key } = req.body || {};

  if (!validateTextAndPassword(text, key)) {
    return res.status(400).json({
      error:
        "Text and password are required. Text must be no larger than 500 KB.",
    });
  }

  try {
    const result = await encryptWithPassword(text, key);

    return res.json({
      result,
      algorithm: "AES-256-GCM",
      version: 1,
    });
  } catch {
    return res.status(500).json({
      error: "Encryption failed. Please try again.",
    });
  }
});

// Decryption API
app.post("/api/decrypt", async (req, res) => {
  const { text, key } = req.body || {};

  if (!validateTextAndPassword(text, key)) {
    return res.status(400).json({
      error: "Encrypted text and password are required.",
    });
  }

  try {
    const result = await decryptWithPassword(text, key);

    return res.json({ result });
  } catch {
    return res.status(400).json({
      error:
        "Unable to decrypt: the password is incorrect or the encrypted data was modified.",
    });
  }
});

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Local development server
if (require.main === module) {
  const PORT = process.env.PORT || 5000;

  app.listen(PORT, () => {
    console.log(`API running on port ${PORT}`);
  });
}

// Export the Express app itself for Vercel.
// Preserve named exports for the existing test suite.
app.app = app;
app.encryptWithPassword = encryptWithPassword;
app.decryptWithPassword = decryptWithPassword;

module.exports = app;
