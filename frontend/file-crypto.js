(() => {
    "use strict";

    const MAGIC = new TextEncoder().encode("EDFILE01");
    const PBKDF2_ITERATIONS = 600000;
    const KEY_LENGTH = 256;
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;
    const AUTH_TAG_LENGTH = 16;
    const MAX_FILE_SIZE = 25 * 1024 * 1024;
    const MAX_METADATA_SIZE = 16 * 1024;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder("utf-8", { fatal: true });

    function ensureWebCrypto() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error(
                "Secure encryption is unavailable. Use HTTPS or localhost."
            );
        }
    }

    function validatePassword(password) {
        if (typeof password !== "string" || password.length === 0) {
            throw new Error("Please enter a password.");
        }
    }

    function validateFile(file) {
        if (!file || typeof file.arrayBuffer !== "function") {
            throw new Error("Please select a valid file.");
        }

        if (file.size > MAX_FILE_SIZE) {
            throw new Error("The maximum supported file size is 25 MB.");
        }
    }


    function validateEncryptedFile(file) {
        if (!file || typeof file.arrayBuffer !== "function") {
            throw new Error("Please select a valid encrypted file.");
        }

        const maxEncryptedSize =
            MAX_FILE_SIZE + MAX_METADATA_SIZE +
            MAGIC.length + SALT_LENGTH + IV_LENGTH + 4 +
            AUTH_TAG_LENGTH;

        if (file.size > maxEncryptedSize) {
            throw new Error("The encrypted file is too large.");
        }
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
                salt,
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

    function concatenateBytes(...arrays) {
        const totalLength = arrays.reduce(
            (total, array) => total + array.length,
            0
        );

        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const array of arrays) {
            result.set(array, offset);
            offset += array.length;
        }

        return result;
    }

    function createHeader(salt, iv, metadataBytes) {
        const header = new Uint8Array(
            MAGIC.length + SALT_LENGTH + IV_LENGTH + 4 + metadataBytes.length
        );

        let offset = 0;

        header.set(MAGIC, offset);
        offset += MAGIC.length;

        header.set(salt, offset);
        offset += SALT_LENGTH;

        header.set(iv, offset);
        offset += IV_LENGTH;

        new DataView(header.buffer).setUint32(
            offset,
            metadataBytes.length,
            false
        );

        offset += 4;
        header.set(metadataBytes, offset);

        return header;
    }

    function sanitizeFileName(name) {
        const cleaned = name
            .replace(/[\/\\]/g, "_")
            .replace(/[\u0000-\u001F\u007F]/g, "")
            .trim();

        if (
            !cleaned ||
            cleaned === "." ||
            cleaned === ".."
        ) {
            return "decrypted-file";
        }

        return cleaned.slice(0, 200);
    }

    async function encryptFile(file, password) {
        ensureWebCrypto();
        validateFile(file);
        validatePassword(password);

        const salt = crypto.getRandomValues(
            new Uint8Array(SALT_LENGTH)
        );

        const iv = crypto.getRandomValues(
            new Uint8Array(IV_LENGTH)
        );

        const metadata = {
            version: 1,
            kdf: "pbkdf2-sha256",
            iterations: PBKDF2_ITERATIONS,
            cipher: "aes-256-gcm",
            originalName: sanitizeFileName(file.name || "file"),
            mimeType: file.type || "application/octet-stream",
            originalSize: file.size
        };

        const metadataBytes = encoder.encode(JSON.stringify(metadata));

        if (metadataBytes.length > MAX_METADATA_SIZE) {
            throw new Error("File metadata is too large.");
        }

        const header = createHeader(salt, iv, metadataBytes);
        const key = await deriveKey(password, salt);
        const fileBytes = await file.arrayBuffer();

        const encryptedBytes = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv,
                    additionalData: header,
                    tagLength: AUTH_TAG_LENGTH * 8
                },
                key,
                fileBytes
            )
        );

        const output = concatenateBytes(header, encryptedBytes);

        return {
            blob: new Blob(
                [output],
                { type: "application/octet-stream" }
            ),
            fileName: sanitizeFileName(file.name || "file") + ".encrypted"
        };
    }

    async function decryptFile(file, password) {
        ensureWebCrypto();
        validateEncryptedFile(file);
        validatePassword(password);

        const data = new Uint8Array(await file.arrayBuffer());

        const minimumLength =
            MAGIC.length + SALT_LENGTH + IV_LENGTH + 4 +
            AUTH_TAG_LENGTH;

        if (data.length < minimumLength) {
            throw new Error("Invalid or incomplete encrypted file.");
        }

        let offset = 0;

        for (let i = 0; i < MAGIC.length; i++) {
            if (data[offset + i] !== MAGIC[i]) {
                throw new Error("Unsupported encrypted file format.");
            }
        }

        offset += MAGIC.length;

        const salt = data.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const iv = data.slice(offset, offset + IV_LENGTH);
        offset += IV_LENGTH;

        const metadataLength = new DataView(
            data.buffer,
            data.byteOffset,
            data.byteLength
        ).getUint32(offset, false);

        offset += 4;

        if (
            metadataLength === 0 ||
            metadataLength > MAX_METADATA_SIZE
        ) {
            throw new Error("Invalid encrypted file metadata.");
        }

        const headerLength = offset + metadataLength;

        if (
            headerLength > data.length ||
            data.length - headerLength < AUTH_TAG_LENGTH
        ) {
            throw new Error("Invalid or incomplete encrypted file.");
        }

        const header = data.slice(0, headerLength);
        const metadataBytes = data.slice(offset, headerLength);

        let metadata;

        try {
            metadata = JSON.parse(decoder.decode(metadataBytes));
        } catch {
            throw new Error("Invalid encrypted file metadata.");
        }

        if (
            !metadata ||
            metadata.version !== 1 ||
            metadata.kdf !== "pbkdf2-sha256" ||
            metadata.iterations !== PBKDF2_ITERATIONS ||
            metadata.cipher !== "aes-256-gcm" ||
            typeof metadata.originalName !== "string" ||
            typeof metadata.mimeType !== "string" ||
            !Number.isSafeInteger(metadata.originalSize) ||
            metadata.originalSize < 0 ||
            metadata.originalSize > MAX_FILE_SIZE ||
            metadata.originalName.length > 200 ||
            metadata.mimeType.length > 200
        ) {
            throw new Error("Unsupported or invalid encrypted file.");
        }

        const encryptedBytes = data.slice(headerLength);

        if (
            encryptedBytes.length !==
            metadata.originalSize + AUTH_TAG_LENGTH
        ) {
            throw new Error("Encrypted file size does not match its metadata.");
        }

        try {
            const key = await deriveKey(password, salt);

            const decryptedBytes = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv,
                    additionalData: header,
                    tagLength: AUTH_TAG_LENGTH * 8
                },
                key,
                encryptedBytes
            );

            return {
                blob: new Blob(
                    [decryptedBytes],
                    {
                        type: metadata.mimeType ||
                            "application/octet-stream"
                    }
                ),
                fileName: sanitizeFileName(metadata.originalName)
            };

        } catch {
            throw new Error(
                "Wrong password or encrypted file has been modified."
            );
        }
    }

    window.FileCrypto = Object.freeze({
        encryptFile,
        decryptFile,
        MAX_FILE_SIZE
    });
})();
