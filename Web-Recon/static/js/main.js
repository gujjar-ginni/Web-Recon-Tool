/**
 * Main application JavaScript
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme from localStorage or default
    const initTheme = () => {
        const savedTheme = localStorage.getItem('selectedTheme') || 'high-visibility';
        const themeSwitcher = document.getElementById('theme-switcher');
        
        if (themeSwitcher) {
            themeSwitcher.value = savedTheme;
            loadTheme(savedTheme);
        }
    };

    // Load theme CSS
    const loadTheme = (themeName) => {
        const themeCSS = document.getElementById('theme-css');
        themeCSS.href = `/static/css/${themeName}.css`;
        localStorage.setItem('selectedTheme', themeName);
    };

    // Setup theme switcher
    const setupThemeSwitcher = () => {
        const themeSwitcher = document.getElementById('theme-switcher');
        if (themeSwitcher) {
            themeSwitcher.addEventListener('change', function() {
                loadTheme(this.value);
            });
        }
    };

    // Setup mobile menu toggle
    const setupMobileMenu = () => {
        const navbarToggler = document.querySelector('.navbar-toggler');
        if (navbarToggler) {
            navbarToggler.addEventListener('click', function() {
                document.querySelector('#main-nav').classList.toggle('show');
            });
        }
    };

    // Initialize all components
    initTheme();
    setupThemeSwitcher();
    setupMobileMenu();

    // Add ARIA attributes dynamically
    document.querySelectorAll('[data-bs-toggle="dropdown"]').forEach(el => {
        el.setAttribute('aria-expanded', 'false');
        el.addEventListener('click', function() {
            const expanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !expanded);
        });
    });
});