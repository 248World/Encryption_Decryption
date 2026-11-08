
const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");

// Provide the browser crypto interface used by file-crypto.js.
global.window = { crypto: webcrypto };

require(path.join(__dirname, "../../frontend/file-crypto.js"));

const {
    encryptFile,
    decryptFile,
    MAX_FILE_SIZE
} = window.FileCrypto;

const password = "CipherNest-Test-Password-2026!";
const legacyPassword = "Legacy-V1-Test-Password-2026!";

const originalText = "CipherNest automated file encryption test.";

let originalFile;
let encryptedResult;
let encryptedFile;
let legacyFile;

// Create the shared v2 test file.
before(async () => {
    originalFile = new File(
        [originalText],
        "confidential-report.txt",
        { type: "text/plain" }
    );

    encryptedResult = await encryptFile(originalFile, password);

    encryptedFile = new File(
        [encryptedResult.blob],
        encryptedResult.fileName,
        { type: "application/octet-stream" }
    );

    // Generate a genuine legacy v1 encrypted file independently.
    const legacyOriginal = new File(
        ["Legacy CipherNest compatibility test."],
        "legacy-report.txt",
        { type: "text/plain" }
    );

    legacyFile = await createLegacyV1Fixture(
        legacyOriginal,
        legacyPassword
    );
});

// Independently generate a legacy v1 encrypted file.
// This reproduces the original v1 format without using
// the production encryption function.
async function createLegacyV1Fixture(file, legacyPassword) {
    const encoder = new TextEncoder();

    const passwordBytes = encoder.encode(legacyPassword);

    const salt = webcrypto.getRandomValues(
        new Uint8Array(16)
    );

    const iv = webcrypto.getRandomValues(
        new Uint8Array(12)
    );

    const passwordKey = await webcrypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await webcrypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 600000,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt"]
    );

    const metadata = {
        version: 1,
        kdf: "pbkdf2-sha256",
        iterations: 600000,
        cipher: "aes-256-gcm",
        originalName: file.name,
        mimeType: file.type || "application/octet-stream",
        originalSize: file.size
    };

    const metadataBytes = encoder.encode(
        JSON.stringify(metadata)
    );

    const headerLength =
        8 + 16 + 12 + 4 + metadataBytes.length;

    const header = new Uint8Array(headerLength);

    let offset = 0;

    header.set(encoder.encode("EDFILE01"), offset);
    offset += 8;

    header.set(salt, offset);
    offset += 16;

    header.set(iv, offset);
    offset += 12;

    new DataView(header.buffer).setUint32(
        offset,
        metadataBytes.length,
        false
    );

    offset += 4;

    header.set(metadataBytes, offset);

    const fileBytes = new Uint8Array(
        await file.arrayBuffer()
    );

    const encryptedBytes = new Uint8Array(
        await webcrypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: header,
                tagLength: 128
            },
            key,
            fileBytes
        )
    );

    const output = new Uint8Array(
        header.length + encryptedBytes.length
    );

    output.set(header);
    output.set(encryptedBytes, header.length);

    return new File(
        [output],
        "legacy-v1-test.encrypted",
        { type: "application/octet-stream" }
    );
}

// --------------------------------------------------
// Current v2 format tests
// --------------------------------------------------

test("encrypts files using the generic v2 download filename", async () => {
    assert.ok(encryptedResult.blob.size > 0);

    assert.equal(
        encryptedResult.fileName,
        "ciphernest-encrypted-file.encrypted"
    );

    const bytes = new Uint8Array(
        await encryptedResult.blob.arrayBuffer()
    );

    const magic = new TextDecoder().decode(
        bytes.slice(0, 8)
    );

    assert.equal(magic, "EDFILE02");
});

test("restores the original content, filename, and MIME type", async () => {
    const decrypted = await decryptFile(
        encryptedFile,
        password
    );

    assert.equal(
        await decrypted.blob.text(),
        originalText
    );

    assert.equal(
        decrypted.fileName,
        "confidential-report.txt"
    );

    assert.equal(
        decrypted.blob.type,
        "text/plain"
    );
});

test("rejects an incorrect password", async () => {
    await assert.rejects(
        decryptFile(
            encryptedFile,
            "Incorrect-Password-123!"
        )
    );
});

test("rejects modified encrypted data", async () => {
    const modifiedBytes = new Uint8Array(
        await encryptedResult.blob.arrayBuffer()
    );

    modifiedBytes[modifiedBytes.length - 1] ^= 1;

    const modifiedFile = new File(
        [modifiedBytes],
        "modified.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(modifiedFile, password)
    );
});

test("keeps the original filename, MIME type, and content hidden", async () => {
    const bytes = new Uint8Array(
        await encryptedResult.blob.arrayBuffer()
    );

    const raw = new TextDecoder().decode(bytes);

    assert.equal(
        raw.includes("confidential-report.txt"),
        false
    );

    assert.equal(
        raw.includes("text/plain"),
        false
    );

    assert.equal(
        raw.includes(originalText),
        false
    );
});

test("restores an empty file", async () => {
    const emptyFile = new File(
        [],
        "empty.txt",
        { type: "text/plain" }
    );

    const encrypted = await encryptFile(
        emptyFile,
        password
    );

    const decrypted = await decryptFile(
        new File(
            [encrypted.blob],
            encrypted.fileName
        ),
        password
    );

    assert.equal(decrypted.blob.size, 0);
    assert.equal(decrypted.fileName, "empty.txt");
});

test("preserves binary file content", async () => {
    const originalBytes = new Uint8Array([
        0, 1, 2, 127, 128, 200, 255
    ]);

    const binaryFile = new File(
        [originalBytes],
        "binary.bin",
        { type: "application/octet-stream" }
    );

    const encrypted = await encryptFile(
        binaryFile,
        password
    );

    const decrypted = await decryptFile(
        new File(
            [encrypted.blob],
            encrypted.fileName
        ),
        password
    );

    const restoredBytes = new Uint8Array(
        await decrypted.blob.arrayBuffer()
    );

    assert.deepEqual(
        restoredBytes,
        originalBytes
    );
});

test("uses a fresh salt and IV for every encryption", async () => {
    const first = await encryptFile(
        originalFile,
        password
    );

    const second = await encryptFile(
        originalFile,
        password
    );

    const firstBytes = new Uint8Array(
        await first.blob.arrayBuffer()
    );

    const secondBytes = new Uint8Array(
        await second.blob.arrayBuffer()
    );

    // v2 header: 8-byte magic, 16-byte salt, 12-byte IV.
    const firstSalt = firstBytes.slice(8, 24);
    const secondSalt = secondBytes.slice(8, 24);

    const firstIV = firstBytes.slice(24, 36);
    const secondIV = secondBytes.slice(24, 36);

    assert.notDeepEqual(firstSalt, secondSalt);
    assert.notDeepEqual(firstIV, secondIV);
});

test("rejects files larger than the supported maximum", async () => {
    const oversizedFile = {
        name: "too-large.bin",
        type: "application/octet-stream",
        size: MAX_FILE_SIZE + 1,
        arrayBuffer: async () => new ArrayBuffer(0)
    };

    await assert.rejects(
        encryptFile(oversizedFile, password),
        /maximum supported file size/i
    );
});

// --------------------------------------------------
// Legacy v1 backward-compatibility tests
// --------------------------------------------------

test("decrypts legacy v1 files and restores their metadata", async () => {
    const decrypted = await decryptFile(
        legacyFile,
        legacyPassword
    );

    assert.equal(
        await decrypted.blob.text(),
        "Legacy CipherNest compatibility test."
    );

    assert.equal(
        decrypted.fileName,
        "legacy-report.txt"
    );

    assert.equal(
        decrypted.blob.type,
        "text/plain"
    );
});

test("rejects an incorrect password for legacy v1 files", async () => {
    await assert.rejects(
        decryptFile(
            legacyFile,
            "Incorrect-Legacy-Password!"
        )
    );
});

test("rejects modified legacy v1 encrypted files", async () => {
    const modifiedBytes = new Uint8Array(
        await legacyFile.arrayBuffer()
    );

    modifiedBytes[modifiedBytes.length - 1] ^= 1;

    const modifiedFile = new File(
        [modifiedBytes],
        "modified-legacy.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(
            modifiedFile,
            legacyPassword
        )
    );
});



test("rejects truncated v2 encrypted files", async () => {
    const bytes = new Uint8Array(
        await encryptedResult.blob.arrayBuffer()
    );

    const truncatedFile = new File(
        [bytes.slice(0, 20)],
        "truncated-v2.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(truncatedFile, password),
        /incomplete encrypted file/i
    );
});

test("rejects truncated legacy v1 encrypted files", async () => {
    const bytes = new Uint8Array(
        await legacyFile.arrayBuffer()
    );

    const truncatedFile = new File(
        [bytes.slice(0, 20)],
        "truncated-v1.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(truncatedFile, legacyPassword),
        /incomplete encrypted file/i
    );
});

test("rejects unsupported encrypted file formats", async () => {
    const unsupportedFile = new File(
        [new TextEncoder().encode("UNKNOWN1")],
        "unsupported.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(unsupportedFile, password),
        /unsupported encrypted file format/i
    );
});

test("rejects invalid legacy v1 metadata lengths", async () => {
    const bytes = new Uint8Array(
        await legacyFile.arrayBuffer()
    );

    // V1 metadata length is stored at byte offset 36.
    new DataView(bytes.buffer).setUint32(
        36,
        0xffffffff,
        false
    );

    const malformedFile = new File(
        [bytes],
        "invalid-metadata-length.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(malformedFile, legacyPassword),
        /invalid encrypted file metadata/i
    );
});

test("rejects modified legacy v1 authenticated metadata", async () => {
    const bytes = new Uint8Array(
        await legacyFile.arrayBuffer()
    );

    const raw = new TextDecoder().decode(bytes);
    const nameIndex = raw.indexOf("legacy-report.txt");

    assert.notEqual(nameIndex, -1);

    // Change one character without changing the JSON structure.
    bytes[nameIndex] = "L".charCodeAt(0);

    const modifiedFile = new File(
        [bytes],
        "modified-v1-metadata.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(modifiedFile, legacyPassword)
    );
});

test("rejects modified v2 authenticated headers", async () => {
    const bytes = new Uint8Array(
        await encryptedResult.blob.arrayBuffer()
    );

    // The salt begins immediately after the 8-byte magic value.
    bytes[8] ^= 1;

    const modifiedFile = new File(
        [bytes],
        "modified-v2-header.encrypted",
        { type: "application/octet-stream" }
    );

    await assert.rejects(
        decryptFile(modifiedFile, password)
    );
});


test("accepts a password at the 1024-byte UTF-8 limit", async () => {
    const boundaryPassword = "é".repeat(512);

    assert.equal(
        new TextEncoder().encode(boundaryPassword).length,
        1024
    );

    const encrypted = await encryptFile(
        originalFile,
        boundaryPassword
    );

    assert.ok(encrypted.blob.size > 0);
});

test("rejects passwords exceeding the 1024-byte UTF-8 limit", async () => {
    const oversizedPassword = "é".repeat(513);

    assert.equal(
        new TextEncoder().encode(oversizedPassword).length,
        1026
    );

    await assert.rejects(
        encryptFile(originalFile, oversizedPassword),
        /password exceeds the maximum supported size/i
    );
});

test("rejects an empty password", async () => {
    await assert.rejects(
        encryptFile(originalFile, ""),
        /please enter a password/i
    );
});

test("accepts a file exactly at the 25 MiB limit", async () => {
    const maximumFile = new File(
        [new Uint8Array(MAX_FILE_SIZE)],
        "maximum-size-test.bin",
        { type: "application/octet-stream" }
    );

    const encrypted = await encryptFile(
        maximumFile,
        password
    );

    assert.ok(encrypted.blob.size > MAX_FILE_SIZE);
    assert.equal(
        encrypted.fileName,
        "ciphernest-encrypted-file.encrypted"
    );
});

test("rejects encrypted files exceeding the permitted size", async () => {
    const maximumEncryptedSize =
        MAX_FILE_SIZE +
        16 * 1024 +
        4 +
        8 +
        16 +
        12 +
        16;

    const oversizedEncryptedFile = {
        name: "oversized.encrypted",
        type: "application/octet-stream",
        size: maximumEncryptedSize + 1,
        arrayBuffer: async () => new ArrayBuffer(0)
    };

    await assert.rejects(
        decryptFile(oversizedEncryptedFile, password),
        /encrypted file is too large/i
    );
});

test("sanitizes reserved filenames before restoring them", async () => {
    const content = new TextEncoder().encode("Filename security test.");

    const unsafeFile = {
        name: "CON.txt",
        type: "text/plain",
        size: content.length,
        arrayBuffer: async () => content.slice().buffer
    };

    const encrypted = await encryptFile(unsafeFile, password);

    const decrypted = await decryptFile(
        new File([encrypted.blob], encrypted.fileName),
        password
    );

    assert.equal(decrypted.fileName, "_CON.txt");
    assert.equal(await decrypted.blob.text(), "Filename security test.");
});

test("replaces invalid MIME metadata with a safe default", async () => {
    const content = new TextEncoder().encode("MIME security test.");

    const fileWithInvalidMime = {
        name: "mime-test.bin",
        type: "not a valid MIME type",
        size: content.length,
        arrayBuffer: async () => content.slice().buffer
    };

    const encrypted = await encryptFile(fileWithInvalidMime, password);

    const decrypted = await decryptFile(
        new File([encrypted.blob], encrypted.fileName),
        password
    );

    assert.equal(
        decrypted.blob.type,
        "application/octet-stream"
    );

    assert.equal(await decrypted.blob.text(), "MIME security test.");
});
