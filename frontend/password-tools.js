
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
        } catch (error) {
            console.error('Password copy failed:', error);
            showMessage(
                'Copy failed. Please copy the password manually.',
                'error'
            );
        }
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
        strength.innerHTML = `
            <div class="password-strength-track">
                <div class="password-strength-fill"></div>
            </div>
            <span class="password-strength-label">
                Enter a password
            </span>
        `;

        const actions = document.createElement('div');
        actions.className = 'password-tool-actions';
        actions.innerHTML = `
            <button type="button" class="password-generate">
                <i class="fas fa-random"></i> Generate password
            </button>
            <button type="button" class="password-copy">
                <i class="fas fa-copy"></i> Copy password
            </button>
        `;

        const status = document.createElement('p');
        status.className = 'password-tool-status';
        status.setAttribute('aria-live', 'polite');

        const container = document.createElement('div');
        container.className = 'password-tools-container';
        container.append(strength, actions, status);

        wrapper.parentNode.insertBefore(container, wrapper.nextSibling);

        const fill = strength.querySelector('.password-strength-fill');
        const label = strength.querySelector('.password-strength-label');

        function updateStrength() {
            const result = getPasswordStrength(input.value);

            label.textContent = result.label;
            fill.className = 'password-strength-fill';

            if (result.level > 0) {
                fill.classList.add(`strength-${result.level}`);
            }

            fill.style.width = `${result.level * 33.333}%`;
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

        actions.querySelector('.password-generate')
            .addEventListener('click', () => {
                input.value = generatePassword();
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.focus();

                status.textContent = 'A secure password was generated.';
            });

        actions.querySelector('.password-copy')
            .addEventListener('click', () => copyPassword(input));

        updateStrength();
    }

    window.addEventListener('DOMContentLoaded', () => {
        ['encrypt-key', 'decrypt-key'].forEach(id => {
            const input = document.getElementById(id);

            if (input) {
                initializePasswordTools(input);
            }
        });
    });
})();
