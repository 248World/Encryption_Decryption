const { webcrypto } = require("node:crypto");

global.window = { crypto: webcrypto };

require("./frontend/file-crypto.js");

const { encryptFile, decryptFile } = window.FileCrypto;

async function runEdgeTests() {
    const password = "EdgeTest-2026!";

    console.log("\nTEST 5: Empty file");

    const emptyFile = new File([], "empty.txt", {
        type: "text/plain"
    });

    const encryptedEmpty = await encryptFile(emptyFile, password);

    const decryptedEmpty = await decryptFile(
        new File([encryptedEmpty.blob], encryptedEmpty.fileName),
        password
    );

    console.log("Empty file restored:", decryptedEmpty.blob.size === 0);

    console.log("\nTEST 6: Binary file");

    const originalBytes = new Uint8Array([0, 1, 2, 127, 128, 200, 255]);

    const binaryFile = new File([originalBytes], "binary.bin", {
        type: "application/octet-stream"
    });

    const encryptedBinary = await encryptFile(binaryFile, password);

    const decryptedBinary = await decryptFile(
        new File([encryptedBinary.blob], encryptedBinary.fileName),
        password
    );

    const restoredBytes = new Uint8Array(
        await decryptedBinary.blob.arrayBuffer()
    );

    console.log(
        "Binary content restored:",
        originalBytes.length === restoredBytes.length &&
        originalBytes.every((value, index) => value === restoredBytes[index])
    );

    console.log("\nTEST 7: Fresh salt and IV");

    const first = await encryptFile(binaryFile, password);
    const second = await encryptFile(binaryFile, password);

    const firstBytes = new Uint8Array(await first.blob.arrayBuffer());
    const secondBytes = new Uint8Array(await second.blob.arrayBuffer());

    const headerLength = 8 + 16 + 12;

    const firstHeader = firstBytes.slice(0, headerLength);
    const secondHeader = secondBytes.slice(0, headerLength);

    const headersAreDifferent = firstHeader.some(
        (value, index) => value !== secondHeader[index]
    );

    console.log("Fresh salt/IV values used:", headersAreDifferent);

    console.log("\nTEST 8: Reject oversized original file");

    const oversizedFile = {
        name: "too-large.bin",
        type: "application/octet-stream",
        size: window.FileCrypto.MAX_FILE_SIZE + 1,
        arrayBuffer: async () => new ArrayBuffer(0)
    };

    try {
        await encryptFile(oversizedFile, password);
        console.log("FAILED: Oversized file was accepted.");
    } catch (error) {
        console.log("Oversized file rejected:", error.message);
    }

    console.log("\nEdge-case tests finished.");
}

runEdgeTests().catch(error => {
    console.error("\nTEST ERROR:", error);
    process.exitCode = 1;
});
