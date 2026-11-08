
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
    let downloadUrl = null;
    let downloadCleanupTimer = null;
    let isProcessing = false;

    function setButtonContent(button, iconClass, label) {
        const icon = document.createElement("i");
        icon.className = iconClass;
        icon.setAttribute("aria-hidden", "true");

        button.replaceChildren(
            icon,
            document.createTextNode(` ${label}`)
        );
    }

    function setPasswordToggleIcon(showPassword) {
        const icon = document.createElement("i");

        icon.className = showPassword
            ? "fas fa-eye-slash"
            : "fas fa-eye";

        icon.setAttribute("aria-hidden", "true");

        passwordToggle.replaceChildren(icon);
        passwordToggle.setAttribute(
            "aria-label",
            showPassword ? "Hide password" : "Show password"
        );
    }

    function showStatus(message, type) {
        statusBox.textContent = message;
        statusBox.className = `file-status ${type}`;
        statusBox.hidden = false;
    }

    function hideStatus() {
        statusBox.hidden = true;
        statusBox.textContent = "";
    }

    function revokeDownloadUrl() {
        if (downloadCleanupTimer !== null) {
            window.clearTimeout(downloadCleanupTimer);
            downloadCleanupTimer = null;
        }

        if (downloadUrl !== null) {
            URL.revokeObjectURL(downloadUrl);
            downloadUrl = null;
        }
    }

    function clearResult() {
        revokeDownloadUrl();

        resultBox.hidden = true;
        resultTitle.textContent = "";
        resultDescription.textContent = "";

        downloadBlob = null;
        downloadFileName = "";
    }

    function setMode(mode) {
        if (isProcessing) return;

        currentMode = mode;

        const encrypting = mode === "encrypt";

        encryptModeButton.classList.toggle("active", encrypting);
        decryptModeButton.classList.toggle("active", !encrypting);

        encryptModeButton.setAttribute("aria-pressed", String(encrypting));
        decryptModeButton.setAttribute("aria-pressed", String(!encrypting));

        document.getElementById("file-upload-title").textContent =
            encrypting
                ? "Choose a file to encrypt"
                : "Choose a file to decrypt";

        setButtonContent(
            submitButton,
            encrypting ? "fas fa-lock" : "fas fa-lock-open",
            encrypting ? "Encrypt File" : "Decrypt File"
        );

        fileInput.accept = encrypting ? "" : ".encrypted";

        selectedFile = null;
        fileInput.value = "";
        selectedName.textContent = "No file selected";

        passwordInput.value = "";
        hideStatus();
        clearResult();
    }

    function selectFile(file) {
        if (!file || isProcessing) return;

        selectedFile = file;
        selectedName.textContent =
            `${file.name} (${formatSize(file.size)})`;

        passwordInput.value = "";
        hideStatus();
        clearResult();
    }

    function formatSize(bytes) {
        if (bytes < 1024) return `${bytes} B`;

        if (bytes < 1024 * 1024) {
            return `${(bytes / 1024).toFixed(1)} KB`;
        }

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

    function setProcessingState(processing, mode = currentMode) {
        isProcessing = processing;

        submitButton.disabled = processing;
        browseButton.disabled = processing;
        encryptModeButton.disabled = processing;
        decryptModeButton.disabled = processing;

        passwordInput.disabled = processing;
        passwordToggle.disabled = processing;

        dropArea.setAttribute(
            "aria-disabled",
            String(processing)
        );

        if (processing) {
            setButtonContent(
                submitButton,
                "fas fa-spinner fa-spin",
                mode === "encrypt" ? "Encrypting File..." : "Decrypting File..."
            );
        } else {
            setButtonContent(
                submitButton,
                mode === "encrypt" ? "fas fa-lock" : "fas fa-lock-open",
                mode === "encrypt" ? "Encrypt File" : "Decrypt File"
            );
        }
    }

    browseButton.addEventListener("click", () => {
        if (!isProcessing) {
            fileInput.click();
        }
    });

    fileInput.addEventListener("change", () => {
        if (!isProcessing) {
            selectFile(fileInput.files[0]);
        }
    });

    encryptModeButton.addEventListener("click", () => {
        setMode("encrypt");
    });

    decryptModeButton.addEventListener("click", () => {
        setMode("decrypt");
    });

    passwordToggle.addEventListener("click", () => {
        if (isProcessing) return;

        const isPassword = passwordInput.type === "password";

        passwordInput.type = isPassword ? "text" : "password";
        setPasswordToggleIcon(isPassword);
    });

    dropArea.addEventListener("dragover", (event) => {
        if (isProcessing) return;

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

        if (isProcessing) return;

        const file = event.dataTransfer.files[0];
        selectFile(file);
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        if (isProcessing || !validateSelection()) return;

        if (!window.FileCrypto) {
            showStatus(
                "The file encryption engine could not be loaded. Please refresh the page.",
                "error"
            );
            passwordInput.value = "";
            return;
        }

        const fileToProcess = selectedFile;
        let password = passwordInput.value;
        const modeToProcess = currentMode;
        const startTime = performance.now();

        setProcessingState(true, modeToProcess);
        clearResult();

        showStatus(
            modeToProcess === "encrypt"
                ? "Encrypting your file. Please wait..."
                : "Decrypting your file. Please wait...",
            "loading"
        );

        try {
            let result;

            if (modeToProcess === "encrypt") {
                result = await window.FileCrypto.encryptFile(
                    fileToProcess,
                    password
                );
            } else {
                result = await window.FileCrypto.decryptFile(
                    fileToProcess,
                    password
                );
            }

            downloadBlob = result.blob;
            downloadFileName = result.fileName;

            resultTitle.textContent =
                modeToProcess === "encrypt"
                    ? "File encrypted successfully!"
                    : "File decrypted successfully!";

            resultDescription.textContent =
                `Your file is ready to download: ${downloadFileName}`;

            resultBox.hidden = false;

            showStatus(
                "Operation completed successfully.",
                "success"
            );

        } catch (error) {
            if (
                error &&
                (
                    error.name === "OperationError" ||
                    error.name === "DataError"
                )
            ) {
                showStatus(
                    "Decryption failed. The password may be incorrect or the file may be damaged.",
                    "error"
                );
            } else {
                showStatus(
                    "Something went wrong while processing the file. Please try again.",
                    "error"
                );
            }
        } finally {
            passwordInput.value = "";
            password = "";

            const elapsed = performance.now() - startTime;
            const remaining = Math.max(0, 400 - elapsed);

            if (remaining > 0) {
                await new Promise(resolve => {
                    window.setTimeout(resolve, remaining);
                });
            }

            setProcessingState(false, modeToProcess);
        }
    });

    downloadButton.addEventListener("click", () => {
        if (!downloadBlob || !downloadFileName) {
            showStatus(
                "There is no processed file to download.",
                "error"
            );
            return;
        }

        if (downloadUrl === null) {
            downloadUrl = URL.createObjectURL(downloadBlob);
        }

        if (downloadCleanupTimer !== null) {
            window.clearTimeout(downloadCleanupTimer);
        }

        const link = document.createElement("a");

        link.href = downloadUrl;
        link.download = downloadFileName;

        document.body.appendChild(link);
        link.click();
        link.remove();

        downloadCleanupTimer = window.setTimeout(() => {
            revokeDownloadUrl();
        }, 1000);
    });

    window.addEventListener("pagehide", () => {
        revokeDownloadUrl();

        selectedFile = null;
        downloadBlob = null;
        downloadFileName = "";

        fileInput.value = "";
        passwordInput.value = "";

        selectedName.textContent = "No file selected";
        resultTitle.textContent = "";
        resultDescription.textContent = "";
        resultBox.hidden = true;

        hideStatus();
    });

    setPasswordToggleIcon(false);
    setMode("encrypt");
})();
