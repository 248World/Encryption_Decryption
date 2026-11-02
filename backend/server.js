const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());

// Only these sites may call the API from a browser
app.use(
  cors({
    origin: [
      "https://encryptiondecryption-frontend.vercel.app",
      "http://localhost:3000",
    ],
  })
);

const ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?";

// Turn the key string into a number, then into a repeatable random generator
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

// Create secret alphabet using key (same key always gives same alphabet)
function makeCipher(key) {
  const rand = seededRandom(hashString(String(key)));
  const secret = ALPHABET.split("");
  for (let i = secret.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [secret[i], secret[j]] = [secret[j], secret[i]];
  }
  const encrypt = new Map();
  const decrypt = new Map();
  for (let i = 0; i < ALPHABET.length; i++) {
    encrypt.set(ALPHABET[i], secret[i]);
    decrypt.set(secret[i], ALPHABET[i]);
  }
  return { encrypt, decrypt };
}

function translate(text, map) {
  return Array.from(text)
    .map((c) => (map.has(c) ? map.get(c) : c))
    .join("");
}

app.post("/api/encrypt", (req, res) => {
  const { text, key } = req.body || {};
  if (!text || !key) return res.status(400).json({ error: "Need text and key" });
  const { encrypt } = makeCipher(key);
  res.json({ result: translate(text, encrypt) });
});

app.post("/api/decrypt", (req, res) => {
  const { text, key } = req.body || {};
  if (!text || !key) return res.status(400).json({ error: "Need text and key" });
  const { decrypt } = makeCipher(key);
  res.json({ result: translate(text, decrypt) });
});

// Simple check that the server is running
app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));