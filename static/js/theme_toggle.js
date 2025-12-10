// theme-toggle.js - Theme switcher with localStorage support
document.addEventListener("DOMContentLoaded", function () {
  console.log("Theme Toggle Script Loaded");

  // Theme toggle button
  const themeToggle = document.getElementById("themeToggle");
  const themeIcon = themeToggle?.querySelector("i");

  // Get current theme from localStorage or default to dark
  const currentTheme = localStorage.getItem("theme") || "dark";

  // Apply theme on page load
  applyTheme(currentTheme);
  updateThemeIcon(currentTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      // Get current theme from data attribute or document
      const currentTheme =
        document.documentElement.getAttribute("data-theme") || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";

      // Apply new theme
      applyTheme(newTheme);
      updateThemeIcon(newTheme);

      // Save to localStorage
      localStorage.setItem("theme", newTheme);

      console.log(`Theme changed to: ${newTheme}`);

      // Dispatch custom event for other components
      document.dispatchEvent(
        new CustomEvent("themeChange", {
          detail: { theme: newTheme },
        })
      );
    });
  }

  // Function to apply theme
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);

    // Update body class for additional styling
    document.body.classList.remove("theme-dark", "theme-light");
    document.body.classList.add(`theme-${theme}`);

    // Update meta theme-color for mobile browsers
    const themeColor = theme === "dark" ? "#000000" : "#f0f9ff"; // Black for dark, light blue for light
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", themeColor);
  }

  // Function to update theme icon
  function updateThemeIcon(theme) {
    if (!themeIcon) return;

    if (theme === "dark") {
      themeIcon.classList.remove("fa-moon");
      themeIcon.classList.add("fa-sun");
      themeIcon.title = "Switch to Light Mode";
    } else {
      themeIcon.classList.remove("fa-sun");
      themeIcon.classList.add("fa-moon");
      themeIcon.title = "Switch to Dark Mode";
    }
  }

  // Initialize password toggles
  initializePasswordToggles();
});

// Password toggle functionality
function initializePasswordToggles() {
  const passwordToggles = document.querySelectorAll(".password-toggle");

  passwordToggles.forEach((toggle) => {
    // Check if already initialized
    if (toggle.getAttribute("data-toggle-initialized")) return;

    toggle.addEventListener("click", function (event) {
      event.preventDefault();

      const targetId = this.getAttribute("data-target");
      const passwordInput = document.getElementById(targetId);

      if (!passwordInput) {
        console.error(`Password input not found: ${targetId}`);
        return;
      }

      const icon = this.querySelector("i");
      if (!icon) return;

      // Toggle visibility
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
      } else {
        passwordInput.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
      }

      // Keep focus
      passwordInput.focus();
    });

    // Mark as initialized
    toggle.setAttribute("data-toggle-initialized", "true");
  });
}

// Check for saved theme preference on page load
window.addEventListener("load", function () {
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme) {
    document.documentElement.setAttribute("data-theme", savedTheme);
  }
});

// Listen for theme changes from other tabs/windows
window.addEventListener("storage", function (event) {
  if (event.key === "theme") {
    applyTheme(event.newValue);
    updateThemeIcon(event.newValue);
  }
});
