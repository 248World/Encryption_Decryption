/**
 * Decryption page behavior.
 * All decryption runs locally through the browser Web Crypto API.
 */

function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    const text = document.getElementById('notification-text');
    const icon = notification.querySelector('i');

    text.textContent = message;

    notification.classList.remove(
        'notification--success',
        'notification--warning',
        'notification--error'
    );

    if (type === 'error') {
        icon.className = 'fas fa-exclamation-circle';
        notification.classList.add('notification--error');
    } else if (type === 'warning') {
        icon.className = 'fas fa-exclamation-triangle';
        notification.classList.add('notification--warning');
    } else {
        icon.className = 'fas fa-check-circle';
        notification.classList.add('notification--success');
    }

    notification.classList.add('show');

    window.setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}


// Safely update button icons and labels without parsing HTML.
function setButtonContent(button, iconClass, label) {
    const icon = document.createElement('i');
    icon.className = iconClass;
    icon.setAttribute('aria-hidden', 'true');

    button.replaceChildren(
        icon,
        document.createTextNode(' ' + label)
    );
}

// Keep this function available to password-tools.js.
window.showNotification = showNotification;


async function decryptText() {
    const textInput = document.getElementById('decrypt-text');
    const keyInput = document.getElementById('decrypt-key');
    const button = document.getElementById('decrypt-button');
    const output = document.getElementById('decrypt-output');

    const text = textInput.value;
    let key = keyInput.value;

    if (!text.trim()) {
        keyInput.value = '';
        key = '';
        showNotification('Please enter text to decrypt!', 'error');
        return;
    }

    if (!key.trim()) {
        keyInput.value = '';
        key = '';
        showNotification('Please enter the secret key!', 'error');
        return;
    }

    output.textContent = '';

    button.disabled = true;
    setButtonContent(button, 'fas fa-spinner fa-spin', 'Decrypting...');

    const startTime = performance.now();

    try {
        const result = await TextCrypto.decryptText(text, key);

        output.textContent = result;

        showNotification(
            'Text decrypted successfully on this device!',
            'success'
        );
    } catch {
        output.textContent = '';

        showNotification(
            'Decryption failed. The password may be incorrect or the data may be damaged.',
            'error'
        );
    } finally {
        // Clear the password after every decryption attempt.
        keyInput.value = '';
        key = '';

        const elapsed = performance.now() - startTime;
        const remaining = Math.max(0, 400 - elapsed);

        if (remaining > 0) {
            await new Promise(resolve => {
                window.setTimeout(resolve, remaining);
            });
        }

        button.disabled = false;
        setButtonContent(button, 'fas fa-unlock', 'Decrypt Text');
    }
}


async function copyResult() {
    const output = document.getElementById('decrypt-output');
    const text = output.textContent;

    if (!text || !text.trim()) {
        showNotification('Nothing to copy yet!', 'warning');
        return;
    }

    const temporaryTextArea = document.createElement('textarea');

    temporaryTextArea.value = text;
    temporaryTextArea.readOnly = true;
    temporaryTextArea.setAttribute('readonly', '');
    temporaryTextArea.setAttribute('spellcheck', 'false');
    temporaryTextArea.setAttribute('autocapitalize', 'off');
    temporaryTextArea.className = 'clipboard-copy-buffer';

    document.body.appendChild(temporaryTextArea);

    try {
        temporaryTextArea.focus();
        temporaryTextArea.select();
        temporaryTextArea.setSelectionRange(0, text.length);

        const copied = document.execCommand('copy');

        if (!copied) {
            throw new Error('Copy operation failed');
        }

        showNotification('Copied exactly to clipboard!', 'success');
    } catch {
        showNotification(
            'Copy failed. Please use normal text selection.',
            'error'
        );
    } finally {
        temporaryTextArea.remove();
    }
}


// Clear sensitive page contents when the user leaves.
window.addEventListener('pagehide', () => {
    document.getElementById('decrypt-text').value = '';
    document.getElementById('decrypt-key').value = '';
    document.getElementById('decrypt-output').textContent = '';
});


// Initialize decryption page events.
window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('decrypt-output').textContent = '';

    document
        .getElementById('decrypt-button')
        .addEventListener('click', decryptText);

    document
        .getElementById('decrypt-copy-button')
        .addEventListener('click', copyResult);
});