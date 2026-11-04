(function () {
    'use strict';

    const STORAGE_KEY = 'encryption-decryption-theme';
    const validPreferences = ['light', 'dark', 'system'];

    function readPreference() {
        try {
            const saved = window.localStorage.getItem(STORAGE_KEY);
            return validPreferences.includes(saved) ? saved : 'light';
        } catch (error) {
            return 'light';
        }
    }

    function resolveTheme(preference) {
        if (preference === 'system') {
            return window.matchMedia &&
                window.matchMedia('(prefers-color-scheme: dark)').matches
                ? 'dark'
                : 'light';
        }

        return preference;
    }

    function applyTheme(preference) {
        const theme = resolveTheme(preference);
        document.documentElement.setAttribute('data-theme', theme);
        document.documentElement.setAttribute(
            'data-theme-preference',
            preference
        );
    }

    let preference = readPreference();

    // Apply the saved theme before the page is displayed to avoid a flash.
    applyTheme(preference);

    function createThemeControl() {
        if (document.querySelector('.theme-toolbar')) {
            return;
        }

        const toolbar = document.createElement('div');
        toolbar.className = 'theme-toolbar';

        const control = document.createElement('div');
        control.className = 'theme-control';

        const label = document.createElement('label');
        label.htmlFor = 'theme-preference';
        label.textContent = 'Theme';

        const select = document.createElement('select');
        select.id = 'theme-preference';
        select.setAttribute('aria-label', 'Choose light, dark, or system theme');

        [
            { value: 'light', text: 'Light' },
            { value: 'dark', text: 'Dark' },
            { value: 'system', text: 'System' }
        ].forEach(optionData => {
            const option = document.createElement('option');
            option.value = optionData.value;
            option.textContent = optionData.text;
            select.appendChild(option);
        });

        select.value = preference;

        select.addEventListener('change', function () {
            preference = validPreferences.includes(select.value)
                ? select.value
                : 'light';

            try {
                window.localStorage.setItem(STORAGE_KEY, preference);
            } catch (error) {
                // The selected theme still works for this page if storage is blocked.
            }

            applyTheme(preference);
        });

        control.append(label, select);
        toolbar.appendChild(control);
        document.body.insertBefore(toolbar, document.body.firstChild);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createThemeControl, {
            once: true
        });
    } else {
        createThemeControl();
    }

    if (window.matchMedia) {
        const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
        const handleSystemThemeChange = function () {
            if (preference === 'system') {
                applyTheme('system');
            }
        };

        if (systemTheme.addEventListener) {
            systemTheme.addEventListener('change', handleSystemThemeChange);
        } else if (systemTheme.addListener) {
            systemTheme.addListener(handleSystemThemeChange);
        }
    }
})();
