
(() => {
    "use strict";

    const fileInput = document.getElementById("file-input");
    const browseButton = document.getElementById("file-browse-btn");
    const dropArea = document.getElementById("file-drop-area");
    const selectedName = document.getElementById("file-selected-name");

    const form = document.getElementById("file-form");
    const passwordInput = document.getElementById("file-password");
    const passwordToggle = document.getElementById("file-password-toggle");

    const encryptModeButton = document.getElementById("file-encrypt-mode");
    const decryptModeButton = document.getElementById("file-decrypt-mode");
    const submitButton = document.getElementById("file-submit-btn");

    const statusBox = document.getElementById("file-status");
    const resultBox = document.getElementById("file-result");
    const resultTitle = document.getElementById("file-result-title");
    const resultDescription = document.getElementById("file-result-description");
    const downloadButton = document.getElementById("file-download-btn");

    let currentMode = "encrypt";
    let selectedFile = null;
    let downloadBlob = null;
    let downloadFileName = "";

    function showStatus(message, type) {
        statusBox.textContent = message;
        statusBox.className = `file-status ${type}`;
        statusBox.hidden = false;
    }

    function hideStatus() {
        statusBox.hidden = true;
        statusBox.textContent = "";
    }

    function clearResult() {
        resultBox.hidden = true;
        downloadBlob = null;
        downloadFileName = "";
    }

    function setMode(mode) {
        currentMode = mode;

        const encrypting = mode === "encrypt";

        encryptModeButton.classList.toggle("active", encrypting);
        decryptModeButton.classList.toggle("active", !encrypting);

        encryptModeButton.setAttribute("aria-pressed", String(encrypting));
        decryptModeButton.setAttribute("aria-pressed", String(!encrypting));

        document.getElementById("file-upload-title").textContent =
            encrypting ? "Choose a file to encrypt" : "Choose a file to decrypt";

        submitButton.innerHTML = encrypting
            ? '<i class="fas fa-lock"></i> Encrypt File'
            : '<i class="fas fa-lock-open"></i> Decrypt File';

        fileInput.accept = encrypting ? "" : ".encrypted";

        selectedFile = null;
        fileInput.value = "";
        selectedName.textContent = "No file selected";

        passwordInput.value = "";
        hideStatus();
        clearResult();
    }

    function selectFile(file) {
        if (!file) return;

        selectedFile = file;
        selectedName.textContent = `${file.name} (${formatSize(file.size)})`;

        hideStatus();
        clearResult();
    }

    function formatSize(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    function validateSelection() {
        if (!selectedFile) {
            showStatus("Please select a file first.", "error");
            return false;
        }

        if (!passwordInput.value) {
            showStatus("Please enter your password.", "error");
            passwordInput.focus();
            return false;
        }

        return true;
    }

    browseButton.addEventListener("click", () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", () => {
        selectFile(fileInput.files[0]);
    });

    encryptModeButton.addEventListener("click", () => {
        setMode("encrypt");
    });

    decryptModeButton.addEventListener("click", () => {
        setMode("decrypt");
    });

    passwordToggle.addEventListener("click", () => {
        const isPassword = passwordInput.type === "password";

        passwordInput.type = isPassword ? "text" : "password";
        passwordToggle.innerHTML = isPassword
            ? '<i class="fas fa-eye-slash"></i>'
            : '<i class="fas fa-eye"></i>';

        passwordToggle.setAttribute(
            "aria-label",
            isPassword ? "Hide password" : "Show password"
        );
    });

    dropArea.addEventListener("dragover", (event) => {
        event.preventDefault();
        dropArea.classList.add("drag-over");
    });

    dropArea.addEventListener("dragleave", (event) => {
        if (!dropArea.contains(event.relatedTarget)) {
            dropArea.classList.remove("drag-over");
        }
    });

    dropArea.addEventListener("drop", (event) => {
        event.preventDefault();
        dropArea.classList.remove("drag-over");

        const file = event.dataTransfer.files[0];
        selectFile(file);
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        if (!validateSelection()) return;

        if (!window.FileCrypto) {
            showStatus("The file encryption engine could not be loaded. Please refresh the page.", "error");
            return;
        }

        const password = passwordInput.value;

        submitButton.disabled = true;
        browseButton.disabled = true;
        encryptModeButton.disabled = true;
        decryptModeButton.disabled = true;

        clearResult();
        showStatus(
            currentMode === "encrypt"
                ? "Encrypting your file. Please wait..."
                : "Decrypting your file. Please wait...",
            "loading"
        );

        try {
            let result;

            if (currentMode === "encrypt") {
                result = await window.FileCrypto.encryptFile(selectedFile, password);
            } else {
                result = await window.FileCrypto.decryptFile(selectedFile, password);
            }

            downloadBlob = result.blob;
            downloadFileName = result.fileName;

            resultTitle.textContent = currentMode === "encrypt"
                ? "File encrypted successfully!"
                : "File decrypted successfully!";

            resultDescription.textContent =
                `Your file is ready to download: ${downloadFileName}`;

            resultBox.hidden = false;
            showStatus("Operation completed successfully.", "success");

        } catch (error) {
            console.error("File processing error:", error);

            if (error.name === "OperationError" || error.name === "DataError") {
                showStatus(
                    "Decryption failed. The password may be incorrect or the file may be damaged.",
                    "error"
                );
            } else {
                showStatus(
                    error.message || "Something went wrong while processing the file.",
                    "error"
                );
            }
        } finally {
            submitButton.disabled = false;
            browseButton.disabled = false;
            encryptModeButton.disabled = false;
            decryptModeButton.disabled = false;
        }
    });

    downloadButton.addEventListener("click", () => {
        if (!downloadBlob || !downloadFileName) {
            showStatus("There is no processed file to download.", "error");
            return;
        }

        const url = URL.createObjectURL(downloadBlob);
        const link = document.createElement("a");

        link.href = url;
        link.download = downloadFileName;

        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });

    setMode("encrypt");
})();
