
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const pbkdf2 = promisify(crypto.pbkdf2);

const FORMAT_PREFIX = "AES256GCM:v1:";
const PBKDF2_ITERATIONS = 600000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

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

async function decryptWithPassword(payload, password) {
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
    !envelope ||
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

module.exports = {
  encryptWithPassword,
  decryptWithPassword,
};
