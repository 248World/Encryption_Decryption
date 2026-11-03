(function () {
    'use strict';

    const STORAGE_KEY = 'secure-crypto-preloader-seen';
    const preloader = document.getElementById('app-preloader');

    if (!preloader) {
        return;
    }

    let alreadySeen = false;

    try {
        alreadySeen = window.sessionStorage.getItem(STORAGE_KEY) === 'yes';
        if (!alreadySeen) {
            window.sessionStorage.setItem(STORAGE_KEY, 'yes');
        }
    } catch (error) {
        // The intro still works if browser storage is unavailable.
    }

    function removePreloader() {
        preloader.classList.add('is-leaving');
        window.setTimeout(function () {
            preloader.remove();
        }, 450);
    }

    if (alreadySeen) {
        preloader.remove();
        return;
    }

    const reducedMotion = window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    window.setTimeout(removePreloader, reducedMotion ? 450 : 1550);
})();
