function initializePasswordToggles() {
  console.log("Toggle Password Script Initializing...");

  const passwordToggles = document.querySelectorAll(".password-toggle");
  console.log(`Found ${passwordToggles.length} password toggle buttons`);

  passwordToggles.forEach((toggle, index) => {
    console.log(`Setting up toggle button ${index + 1}:`, toggle);

    // Remove any existing listeners to prevent duplicates
    toggle.replaceWith(toggle.cloneNode(true));
  });

  // Re-select after cloning
  const freshToggles = document.querySelectorAll(".password-toggle");

  freshToggles.forEach((toggle, index) => {
    toggle.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();

      const targetId = this.getAttribute("data-target");
      console.log(`Button clicked! Target ID: ${targetId}`);

      // Try multiple selectors to find the input
      let passwordInput = document.getElementById(targetId);

      if (!passwordInput) {
        // Try by name attribute
        passwordInput = document.querySelector(`[name="${targetId}"]`);
      }

      if (!passwordInput) {
        console.error(`❌ Password input not found: ${targetId}`);
        return;
      }

      console.log(
        `✅ Found input: ${
          passwordInput.id || passwordInput.name
        }, current type: ${passwordInput.type}`
      );

      const icon = this.querySelector("i");
      if (!icon) {
        console.error("Icon element not found in toggle button");
        return;
      }

      // Toggle password visibility
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
        console.log(
          `Changed ${passwordInput.id || passwordInput.name} to text (visible)`
        );
      } else {
        passwordInput.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
        console.log(
          `Changed ${
            passwordInput.id || passwordInput.name
          } to password (hidden)`
        );
      }

      // Keep focus on the input
      passwordInput.focus();
    });

    // Add a data attribute for debugging
    toggle.setAttribute("data-toggle-initialized", "true");
  });
}

// Initialize on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializePasswordToggles);
} else {
  initializePasswordToggles();
}

// For dynamically added elements (like in your registration form)
document.addEventListener("DOMContentLoaded", function () {
  // Watch for changes in the document
  const observer = new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
      if (mutation.addedNodes.length) {
        // Check if any new password toggle buttons were added
        mutation.addedNodes.forEach(function (node) {
          if (node.nodeType === 1) {
            // Element node
            if (node.classList && node.classList.contains("password-toggle")) {
              console.log("New password toggle detected, reinitializing...");
              initializePasswordToggles();
            } else if (node.querySelectorAll) {
              const newToggles = node.querySelectorAll(".password-toggle");
              if (newToggles.length > 0) {
                console.log(
                  `${newToggles.length} new password toggles detected, reinitializing...`
                );
                initializePasswordToggles();
              }
            }
          }
        });
      }
    });
  });

  // Start observing
  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
});
