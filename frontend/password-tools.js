(() => {
    'use strict';

    const PASSWORD_LENGTH = 20;

    function secureRandomInt(max) {
        const range = 0x100000000;
        const limit = Math.floor(range / max) * max;
        const values = new Uint32Array(1);

        do {
            crypto.getRandomValues(values);
        } while (values[0] >= limit);

        return values[0] % max;
    }

    function generatePassword() {
        const groups = [
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            '!@#$%^&*()-_=+[]{}?'
        ];

        const allCharacters = groups.join('');
        const password = groups.map(group =>
            group[secureRandomInt(group.length)]
        );

        while (password.length < PASSWORD_LENGTH) {
            password.push(
                allCharacters[secureRandomInt(allCharacters.length)]
            );
        }

        // Cryptographically secure Fisher-Yates shuffle.
        for (let i = password.length - 1; i > 0; i--) {
            const j = secureRandomInt(i + 1);
            [password[i], password[j]] = [password[j], password[i]];
        }

        return password.join('');
    }

    function getPasswordStrength(password) {
        if (!password) {
            return {
                label: 'Enter a password',
                level: 0
            };
        }

        let score = 0;

        if (password.length >= 12) score++;
        if (password.length >= 16) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;

        if (password.length < 8 || score <= 2) {
            return { label: 'Weak', level: 1 };
        }

        if (score <= 4) {
            return { label: 'Medium', level: 2 };
        }

        return { label: 'Strong', level: 3 };
    }

    function showMessage(message, type = 'success') {
        if (typeof window.showNotification === 'function') {
            window.showNotification(message, type);
            return;
        }

        const status = document.querySelector('.password-tool-status');

        if (status) {
            status.textContent = message;
        }
    }

    async function copyPassword(input) {
        if (!input.value) {
            showMessage('Generate or enter a password first.', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(input.value);
            showMessage('Password copied to clipboard!', 'success');
        } catch {
            showMessage(
                'Copy failed. Please copy the password manually.',
                'error'
            );
        }
    }

    function createIcon(classNames) {
        const icon = document.createElement('i');
        icon.className = classNames;
        icon.setAttribute('aria-hidden', 'true');
        return icon;
    }

    function initializePasswordTools(input) {
        const wrapper = document.createElement('div');
        wrapper.className = 'password-input-wrapper';

        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'password-toggle';
        toggle.textContent = 'Show';
        toggle.setAttribute('aria-label', 'Show password');
        wrapper.appendChild(toggle);

        const strength = document.createElement('div');
        strength.className = 'password-strength';

        const track = document.createElement('div');
        track.className = 'password-strength-track';

        const fill = document.createElement('div');
        fill.className = 'password-strength-fill';

        track.appendChild(fill);

        const label = document.createElement('span');
        label.className = 'password-strength-label';
        label.textContent = 'Enter a password';

        strength.append(track, label);

        const actions = document.createElement('div');
        actions.className = 'password-tool-actions';

        const generateButton = document.createElement('button');
        generateButton.type = 'button';
        generateButton.className = 'password-generate';
        generateButton.append(
            createIcon('fas fa-random'),
            document.createTextNode(' Generate password')
        );

        const copyButton = document.createElement('button');
        copyButton.type = 'button';
        copyButton.className = 'password-copy';
        copyButton.append(
            createIcon('fas fa-copy'),
            document.createTextNode(' Copy password')
        );

        actions.append(generateButton, copyButton);

        const status = document.createElement('p');
        status.className = 'password-tool-status';
        status.setAttribute('aria-live', 'polite');

        const container = document.createElement('div');
        container.className = 'password-tools-container';
        container.append(strength, actions, status);

        wrapper.parentNode.insertBefore(container, wrapper.nextSibling);

        function updateStrength() {
            const result = getPasswordStrength(input.value);

            label.textContent = result.label;
            fill.className = 'password-strength-fill';

            if (result.level > 0) {
                fill.classList.add(`strength-${result.level}`);
            }
        }

        toggle.addEventListener('click', () => {
            const showing = input.type === 'text';

            input.type = showing ? 'password' : 'text';
            toggle.textContent = showing ? 'Show' : 'Hide';
            toggle.setAttribute(
                'aria-label',
                showing ? 'Show password' : 'Hide password'
            );
        });

        input.addEventListener('input', updateStrength);

        generateButton.addEventListener('click', () => {
            try {
                input.value = generatePassword();
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.focus();

                status.textContent = 'A secure password was generated.';
            } catch {
                status.textContent =
                    'Password generation failed. Please try again.';
            }
        });

        copyButton.addEventListener('click', () => copyPassword(input));

        updateStrength();
    }

    window.addEventListener('DOMContentLoaded', () => {
        ['encrypt-key', 'decrypt-key'].forEach(id => {
            const input = document.getElementById(id);

            if (input && !input.dataset.passwordToolsInitialized) {
                input.dataset.passwordToolsInitialized = 'true';
                initializePasswordTools(input);
            }
        });
    });
})();
