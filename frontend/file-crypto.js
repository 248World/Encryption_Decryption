
(() => {
    "use strict";

    // File format identifiers.
    const MAGIC_V1 = new TextEncoder().encode("EDFILE01");
    const MAGIC_V2 = new TextEncoder().encode("EDFILE02");

    // Cryptographic parameters.
    const PBKDF2_ITERATIONS = 600000;
    const KEY_LENGTH = 256;
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;
    const AUTH_TAG_LENGTH = 16;

    // Input limits.
    const MAX_FILE_SIZE = 25 * 1024 * 1024;
    const MAX_METADATA_SIZE = 16 * 1024;
    const MAX_PASSWORD_BYTES = 1024;

    // Generic download name: does not reveal the original filename.
    const ENCRYPTED_DOWNLOAD_NAME =
        "ciphernest-encrypted-file.encrypted";

    const encoder = new TextEncoder();
    const decoder = new TextDecoder("utf-8", { fatal: true });

    function ensureWebCrypto() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error(
                "Secure encryption is unavailable. Use HTTPS or localhost."
            );
        }
    }

    // Best-effort cleanup. JavaScript and Web Crypto may retain internal copies.
    function clearBytes(...arrays) {
        for (const array of arrays) {
            if (array instanceof Uint8Array) {
                array.fill(0);
            }
        }
    }

    function validatePassword(password) {
        if (typeof password !== "string") {
            throw new Error("Please enter a valid password.");
        }

        if (password.length === 0) {
            throw new Error("Please enter a password.");
        }

        // Reject excessively long strings before allocating UTF-8 bytes.
        if (password.length > MAX_PASSWORD_BYTES) {
            throw new Error("Password exceeds the maximum supported size.");
        }

        const passwordBytes = encoder.encode(password);

        if (
            passwordBytes.length === 0 ||
            passwordBytes.length > MAX_PASSWORD_BYTES
        ) {
            clearBytes(passwordBytes);
            throw new Error("Password exceeds the maximum supported size.");
        }

        return passwordBytes;
    }

    function validateFile(file) {
        if (!file || typeof file.arrayBuffer !== "function") {
            throw new Error("Please select a valid file.");
        }

        if (
            !Number.isSafeInteger(file.size) ||
            file.size < 0 ||
            file.size > MAX_FILE_SIZE
        ) {
            throw new Error("The maximum supported file size is 25 MB.");
        }
    }

    function validateEncryptedFile(file) {
        if (!file || typeof file.arrayBuffer !== "function") {
            throw new Error("Please select a valid encrypted file.");
        }

        // Conservative maximum for both V1 and V2 formats.
        const maxEncryptedSize =
            MAX_FILE_SIZE +
            MAX_METADATA_SIZE +
            4 +
            MAGIC_V1.length +
            SALT_LENGTH +
            IV_LENGTH +
            AUTH_TAG_LENGTH;

        if (
            !Number.isSafeInteger(file.size) ||
            file.size < 0 ||
            file.size > maxEncryptedSize
        ) {
            throw new Error("The encrypted file is too large.");
        }
    }

    async function deriveKey(passwordBytes, salt) {
        const passwordKey = await crypto.subtle.importKey(
            "raw",
            passwordBytes,
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

    function createV2Header(salt, iv) {
        return concatenateBytes(
            MAGIC_V2,
            salt,
            iv
        );
    }

    function hasMagic(data, magic) {
        if (data.length < magic.length) {
            return false;
        }

        for (let i = 0; i < magic.length; i++) {
            if (data[i] !== magic[i]) {
                return false;
            }
        }

        return true;
    }

    function sanitizeFileName(name) {
        let cleaned = (typeof name === "string" ? name : "")
            .replace(/[\/\\<>:"|?*]/g, "_")
            .replace(/[\u0000-\u001F\u007F]/g, "")
            // Remove bidirectional controls that can disguise filenames.
            .replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, "")
            .trim()
            // Windows does not allow filenames ending in spaces or dots.
            .replace(/[ .]+$/g, "");

        if (!cleaned || cleaned === "." || cleaned === "..") {
            return "decrypted-file";
        }

        // Avoid Windows reserved device names.
        if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(cleaned)) {
            cleaned = `_${cleaned}`;
        }

        // Limit by Unicode characters, not UTF-16 code units.
        cleaned = Array.from(cleaned).slice(0, 200).join("");

        return cleaned || "decrypted-file";
    }

    function sanitizeMimeType(value) {
        if (typeof value !== "string" || value.length > 200) {
            return "application/octet-stream";
        }

        const mimeType = value.trim().toLowerCase();

        const validMimeType =
            /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/;

        return validMimeType.test(mimeType)
            ? mimeType
            : "application/octet-stream";
    }

    function createMetadata(file, version) {
        return {
            version,
            kdf: "pbkdf2-sha256",
            iterations: PBKDF2_ITERATIONS,
            cipher: "aes-256-gcm",
            originalName: sanitizeFileName(file.name || "file"),
            mimeType: sanitizeMimeType(file.type),
            originalSize: file.size
        };
    }

    function validateMetadata(metadata, expectedVersion) {
        return Boolean(
            metadata &&
            typeof metadata === "object" &&
            !Array.isArray(metadata) &&
            metadata.version === expectedVersion &&
            metadata.kdf === "pbkdf2-sha256" &&
            metadata.iterations === PBKDF2_ITERATIONS &&
            metadata.cipher === "aes-256-gcm" &&
            typeof metadata.originalName === "string" &&
            typeof metadata.mimeType === "string" &&
            Number.isSafeInteger(metadata.originalSize) &&
            metadata.originalSize >= 0 &&
            metadata.originalSize <= MAX_FILE_SIZE &&
            metadata.originalName.length <= 200 &&
            metadata.mimeType.length <= 200
        );
    }

    function createResult(decryptedBytes, metadata) {
        // Blob takes a snapshot of the supplied bytes.
        return {
            blob: new Blob(
                [decryptedBytes],
                {
                    type: sanitizeMimeType(metadata.mimeType)
                }
            ),
            fileName: sanitizeFileName(metadata.originalName)
        };
    }

    async function encryptFile(file, password) {
        ensureWebCrypto();
        validateFile(file);

        const passwordBytes = validatePassword(password);

        let fileBytes;
        let metadataBytes;
        let metadataLength;
        let header;
        let plaintextPayload;
        let encryptedBytes;
        let output;

        try {
            const salt = crypto.getRandomValues(
                new Uint8Array(SALT_LENGTH)
            );

            const iv = crypto.getRandomValues(
                new Uint8Array(IV_LENGTH)
            );

            // V2 metadata is encrypted together with the original file.
            const metadata = createMetadata(file, 2);

            metadataBytes = encoder.encode(
                JSON.stringify(metadata)
            );

            if (metadataBytes.length > MAX_METADATA_SIZE) {
                throw new Error("File metadata is too large.");
            }

            fileBytes = new Uint8Array(
                await file.arrayBuffer()
            );

            if (
                fileBytes.length !== file.size ||
                fileBytes.length > MAX_FILE_SIZE
            ) {
                throw new Error("The selected file could not be processed.");
            }

            // The public header contains only format, salt and IV.
            header = createV2Header(salt, iv);

            // Encrypt metadata length, metadata and file contents together.
            metadataLength = new Uint8Array(4);

            new DataView(metadataLength.buffer).setUint32(
                0,
                metadataBytes.length,
                false
            );

            plaintextPayload = concatenateBytes(
                metadataLength,
                metadataBytes,
                fileBytes
            );

            const key = await deriveKey(passwordBytes, salt);

            encryptedBytes = new Uint8Array(
                await crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv,
                        additionalData: header,
                        tagLength: AUTH_TAG_LENGTH * 8
                    },
                    key,
                    plaintextPayload
                )
            );

            output = concatenateBytes(
                header,
                encryptedBytes
            );

            // Blob snapshots the encrypted output before cleanup.
            const encryptedBlob = new Blob(
                [output],
                { type: "application/octet-stream" }
            );

            return {
                blob: encryptedBlob,
                fileName: ENCRYPTED_DOWNLOAD_NAME
            };
        } finally {
            clearBytes(
                passwordBytes,
                fileBytes,
                metadataBytes,
                metadataLength,
                header,
                plaintextPayload,
                encryptedBytes,
                output
            );
        }
    }

    async function decryptV1(data, passwordBytes) {
        const minimumLength =
            MAGIC_V1.length +
            SALT_LENGTH +
            IV_LENGTH +
            4 +
            AUTH_TAG_LENGTH;

        if (data.length < minimumLength) {
            throw new Error("Invalid or incomplete encrypted file.");
        }

        let offset = MAGIC_V1.length;

        const salt = data.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const iv = data.slice(offset, offset + IV_LENGTH);
        offset += IV_LENGTH;

        let metadataBytes;
        let header;
        let encryptedBytes;
        let decryptedBytes;

        try {
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

            header = data.slice(0, headerLength);
            metadataBytes = data.slice(offset, headerLength);

            let metadata;

            try {
                metadata = JSON.parse(decoder.decode(metadataBytes));
            } catch {
                throw new Error("Invalid encrypted file metadata.");
            }

            if (!validateMetadata(metadata, 1)) {
                throw new Error("Unsupported or invalid encrypted file.");
            }

            encryptedBytes = data.slice(headerLength);

            if (
                encryptedBytes.length !==
                metadata.originalSize + AUTH_TAG_LENGTH
            ) {
                throw new Error("Encrypted file size does not match its metadata.");
            }

            const key = await deriveKey(passwordBytes, salt);

            try {
                decryptedBytes = new Uint8Array(
                    await crypto.subtle.decrypt(
                        {
                            name: "AES-GCM",
                            iv,
                            additionalData: header,
                            tagLength: AUTH_TAG_LENGTH * 8
                        },
                        key,
                        encryptedBytes
                    )
                );
            } catch {
                throw new Error(
                    "Wrong password or encrypted file has been modified."
                );
            }

            return createResult(decryptedBytes, metadata);
        } finally {
            clearBytes(
                salt,
                iv,
                metadataBytes,
                header,
                encryptedBytes,
                decryptedBytes
            );
        }
    }

    async function decryptV2(data, passwordBytes) {
        const headerLength =
            MAGIC_V2.length +
            SALT_LENGTH +
            IV_LENGTH;

        if (data.length < headerLength + 4 + AUTH_TAG_LENGTH) {
            throw new Error("Invalid or incomplete encrypted file.");
        }

        let offset = MAGIC_V2.length;

        const salt = data.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const iv = data.slice(offset, offset + IV_LENGTH);

        let header;
        let encryptedBytes;
        let decryptedPayload;
        let metadataBytes;
        let fileBytes;

        try {
            // Authenticate the entire public header.
            header = data.slice(0, headerLength);

            encryptedBytes = data.slice(headerLength);

            const key = await deriveKey(passwordBytes, salt);

            try {
                decryptedPayload = new Uint8Array(
                    await crypto.subtle.decrypt(
                        {
                            name: "AES-GCM",
                            iv,
                            additionalData: header,
                            tagLength: AUTH_TAG_LENGTH * 8
                        },
                        key,
                        encryptedBytes
                    )
                );
            } catch {
                throw new Error(
                    "Wrong password or encrypted file has been modified."
                );
            }

            if (decryptedPayload.length < 4) {
                throw new Error("Invalid or damaged encrypted file.");
            }

            const metadataLength = new DataView(
                decryptedPayload.buffer,
                decryptedPayload.byteOffset,
                decryptedPayload.byteLength
            ).getUint32(0, false);

            if (
                metadataLength === 0 ||
                metadataLength > MAX_METADATA_SIZE ||
                metadataLength > decryptedPayload.length - 4
            ) {
                throw new Error("Invalid or damaged encrypted file.");
            }

            metadataBytes = decryptedPayload.slice(
                4,
                4 + metadataLength
            );

            let metadata;

            try {
                metadata = JSON.parse(decoder.decode(metadataBytes));
            } catch {
                throw new Error("Invalid or damaged encrypted file.");
            }

            if (!validateMetadata(metadata, 2)) {
                throw new Error("Invalid or damaged encrypted file.");
            }

            fileBytes = decryptedPayload.slice(
                4 + metadataLength
            );

            if (fileBytes.length !== metadata.originalSize) {
                throw new Error("Invalid or damaged encrypted file.");
            }

            return createResult(fileBytes, metadata);
        } finally {
            clearBytes(
                salt,
                iv,
                header,
                encryptedBytes,
                decryptedPayload,
                metadataBytes,
                fileBytes
            );
        }
    }

    async function decryptFile(file, password) {
        ensureWebCrypto();
        validateEncryptedFile(file);

        const passwordBytes = validatePassword(password);
        let data;

        try {
            data = new Uint8Array(
                await file.arrayBuffer()
            );

            if (hasMagic(data, MAGIC_V1)) {
                return await decryptV1(data, passwordBytes);
            }

            if (hasMagic(data, MAGIC_V2)) {
                return await decryptV2(data, passwordBytes);
            }

            throw new Error("Unsupported encrypted file format.");
        } finally {
            clearBytes(passwordBytes, data);
        }
    }

    window.FileCrypto = Object.freeze({
        encryptFile,
        decryptFile,
        MAX_FILE_SIZE
    });
})();
