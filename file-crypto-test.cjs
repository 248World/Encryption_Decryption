const { webcrypto } = require("node:crypto");

global.window = { crypto: webcrypto };

require("./frontend/file-crypto.js");

const { encryptFile, decryptFile } = window.FileCrypto;

async function runTests() {
    const password = "TestPassword-2026!";
    const originalText = "This is a test file for encryption.";
    const originalFile = new File(
        [originalText],
        "hello.txt",
        { type: "text/plain" }
    );

    console.log("\nTEST 1: Encrypt a file");

    const encrypted = await encryptFile(originalFile, password);

    console.log("Encrypted successfully:", encrypted.blob.size > 0);
    console.log("Encrypted filename:", encrypted.fileName);

    const encryptedFile = new File(
        [encrypted.blob],
        encrypted.fileName,
        { type: "application/octet-stream" }
    );

    console.log("\nTEST 2: Decrypt and compare");

    const decrypted = await decryptFile(encryptedFile, password);
    const decryptedText = await decrypted.blob.text();

    console.log("Original content restored:", decryptedText === originalText);
    console.log("Original filename restored:", decrypted.fileName === "hello.txt");
    console.log("Original MIME type restored:", decrypted.blob.type === "text/plain");

    console.log("\nTEST 3: Reject incorrect password");

    try {
        await decryptFile(encryptedFile, "WrongPassword!");
        console.log("FAILED: Incorrect password was accepted.");
    } catch (error) {
        console.log("Incorrect password rejected:", error.message);
    }

    console.log("\nTEST 4: Detect modified encrypted file");

    const modifiedBytes = new Uint8Array(await encrypted.blob.arrayBuffer());
    modifiedBytes[modifiedBytes.length - 1] ^= 1;

    const modifiedFile = new File(
        [modifiedBytes],
        "modified.encrypted",
        { type: "application/octet-stream" }
    );

    try {
        await decryptFile(modifiedFile, password);
        console.log("FAILED: Modified file was accepted.");
    } catch (error) {
        console.log("Modified file rejected:", error.message);
    }

    console.log("\nAll tests finished.");
}

runTests().catch(error => {
    console.error("\nTEST ERROR:", error);
    process.exitCode = 1;
});
