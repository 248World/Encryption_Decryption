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
      // Requests without an Origin header include local tools and server-to-server calls.
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

// New encryption: AES-256-GCM with a fresh random salt and IV for every message.
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

  return FORMAT_PREFIX + Buffer.from(JSON.stringify(envelope)).toString("base64url");
}

async function decryptWithPassword(payload, password) {
  if (typeof payload !== "string" || !payload.startsWith(FORMAT_PREFIX)) {
    throw new Error("Unsupported encrypted format");
  }

  let envelope;
  try {
    const encoded = payload.slice(FORMAT_PREFIX.length);
    envelope = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
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

  // GCM authentication is checked by final(); a wrong password or modified
  // ciphertext will fail here instead of returning corrupted plaintext.
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}

// Legacy substitution cipher support is retained only for decrypting messages
// created by the previous version of this application. New encryption never uses it.
const LEGACY_ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?";

function hashString(str) {
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  h = Math.imul(h ^ (h >>> 16), 2246822507);
  h = Math.imul(h ^ (h >>> 13), 3266489909);
  return (h ^ (h >>> 16)) >>> 0;
}

function seededRandom(seed) {
  let a = seed;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeLegacyCipher(password) {
  const rand = seededRandom(hashString(String(password)));
  const secret = LEGACY_ALPHABET.split("");
  for (let i = secret.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [secret[i], secret[j]] = [secret[j], secret[i]];
  }

  const decrypt = new Map();
  for (let i = 0; i < LEGACY_ALPHABET.length; i++) {
    decrypt.set(secret[i], LEGACY_ALPHABET[i]);
  }
  return decrypt;
}

function translateLegacy(text, map) {
  return Array.from(text)
    .map((character) => (map.has(character) ? map.get(character) : character))
    .join("");
}

function validateTextAndPassword(text, password) {
  return (
    typeof text === "string" &&
    typeof password === "string" &&
    text.length <= 500000 &&
    password.length > 0 &&
    password.length <= 1024
  );
}

app.post("/api/encrypt", async (req, res) => {
  const { text, key } = req.body || {};
  if (!validateTextAndPassword(text, key)) {
    return res.status(400).json({
      error: "Text and password are required. Text must be no larger than 500 KB.",
    });
  }

  try {
    const result = await encryptWithPassword(text, key);
    return res.json({ result, algorithm: "AES-256-GCM", version: 1 });
  } catch {
    return res.status(500).json({ error: "Encryption failed. Please try again." });
  }
});

app.post("/api/decrypt", async (req, res) => {
  const { text, key } = req.body || {};
  if (!validateTextAndPassword(text, key)) {
    return res.status(400).json({
      error: "Encrypted text and password are required.",
    });
  }

  try {
    let result;
    if (text.startsWith(FORMAT_PREFIX)) {
      result = await decryptWithPassword(text, key);
    } else {
      // Backward compatibility for ciphertext produced by the old demo cipher.
      result = translateLegacy(text, makeLegacyCipher(key));
    }
    return res.json({ result });
  } catch {
    // Do not reveal whether the password was wrong or the data was changed.
    return res.status(400).json({
      error: "Unable to decrypt: the password is incorrect or the encrypted data was modified.",
    });
  }
});

app.get("/health", (_req, res) => res.json({ status: "ok" }));

if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`API running on port ${PORT}`));
}

module.exports = { app, encryptWithPassword, decryptWithPassword };
