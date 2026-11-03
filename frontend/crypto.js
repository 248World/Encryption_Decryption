(() => {
    "use strict";

    const FORMAT_PREFIX = "AES256GCM:v1:";
    const PBKDF2_ITERATIONS = 600000;
    const KEY_LENGTH = 256;
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;
    const AUTH_TAG_LENGTH = 16;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder("utf-8", { fatal: true });

    function ensureWebCrypto() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error(
                "Secure browser encryption is unavailable. Open this page using HTTPS or localhost."
            );
        }
    }

    function bytesToBase64(bytes) {
        let binary = "";
        const chunkSize = 0x8000;

        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(
                ...bytes.subarray(i, i + chunkSize)
            );
        }

        return btoa(binary);
    }

    function base64ToBytes(value) {
        if (
            typeof value !== "string" ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
        ) {
            throw new Error("Invalid encrypted data format.");
        }

        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    }

    function bytesToBase64Url(bytes) {
        return bytesToBase64(bytes)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/g, "");
    }

    function base64UrlToBytes(value) {
        if (
            typeof value !== "string" ||
            !/^[A-Za-z0-9_-]+$/.test(value)
        ) {
            throw new Error("Invalid encrypted data format.");
        }

        const base64 = value
            .replace(/-/g, "+")
            .replace(/_/g, "/");

        return base64ToBytes(
            base64 + "=".repeat((4 - base64.length % 4) % 4)
        );
    }

    async function deriveKey(password, salt) {
        const passwordKey = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            passwordKey,
            {
                name: "AES-GCM",
                length: KEY_LENGTH
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptText(plaintext, password) {
        ensureWebCrypto();

        if (typeof plaintext !== "string" || typeof password !== "string") {
            throw new Error("Text and password must be strings.");
        }

        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

        const key = await deriveKey(password, salt);

        const encrypted = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                    tagLength: AUTH_TAG_LENGTH * 8
                },
                key,
                encoder.encode(plaintext)
            )
        );

        const ciphertext = encrypted.slice(0, -AUTH_TAG_LENGTH);
        const authTag = encrypted.slice(-AUTH_TAG_LENGTH);

        const envelope = {
            version: 1,
            kdf: "pbkdf2-sha256",
            iterations: PBKDF2_ITERATIONS,
            cipher: "aes-256-gcm",
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            authTag: bytesToBase64(authTag),
            ciphertext: bytesToBase64(ciphertext)
        };

        const envelopeBytes = encoder.encode(JSON.stringify(envelope));

        return FORMAT_PREFIX + bytesToBase64Url(envelopeBytes);
    }

    async function decryptText(encryptedText, password) {
        ensureWebCrypto();

        if (
            typeof encryptedText !== "string" ||
            typeof password !== "string"
        ) {
            throw new Error("Encrypted text and password must be strings.");
        }

        const prefix = encryptedText.slice(0, FORMAT_PREFIX.length);

        if (prefix.toLowerCase() !== FORMAT_PREFIX.toLowerCase()) {
            throw new Error("Unsupported or invalid encrypted text format.");
        }

        const payload = encryptedText.slice(FORMAT_PREFIX.length);

        let envelope;

        try {
            const envelopeBytes = base64UrlToBytes(payload);
            envelope = JSON.parse(decoder.decode(envelopeBytes));
        } catch {
            throw new Error("Invalid encrypted data format.");
        }

        if (
            !envelope ||
            envelope.version !== 1 ||
            envelope.kdf !== "pbkdf2-sha256" ||
            envelope.iterations !== PBKDF2_ITERATIONS ||
            envelope.cipher !== "aes-256-gcm"
        ) {
            throw new Error("Unsupported encrypted data format.");
        }

        let salt;
        let iv;
        let authTag;
        let ciphertext;

        try {
            salt = base64ToBytes(envelope.salt);
            iv = base64ToBytes(envelope.iv);
            authTag = base64ToBytes(envelope.authTag);
            ciphertext = base64ToBytes(envelope.ciphertext);
        } catch {
            throw new Error("Invalid encrypted data format.");
        }

        if (
            salt.length !== SALT_LENGTH ||
            iv.length !== IV_LENGTH ||
            authTag.length !== AUTH_TAG_LENGTH
        ) {
            throw new Error("Invalid encrypted data parameters.");
        }

        const encrypted = new Uint8Array(
            ciphertext.length + authTag.length
        );

        encrypted.set(ciphertext);
        encrypted.set(authTag, ciphertext.length);

        try {
            const key = await deriveKey(password, salt);

            const decrypted = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                    tagLength: AUTH_TAG_LENGTH * 8
                },
                key,
                encrypted
            );

            return decoder.decode(decrypted);

        } catch {
            throw new Error(
                "Wrong password or encrypted data has been modified."
            );
        }
    }

    window.TextCrypto = Object.freeze({
        encryptText,
        decryptText
    });
})();
