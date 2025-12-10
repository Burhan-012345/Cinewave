document.addEventListener("DOMContentLoaded", function () {
  const passwordInputs = document.querySelectorAll(".password-validate");

  passwordInputs.forEach((input) => {
    const validationContainer = document.createElement("div");
    validationContainer.className = "validation-container mt-2";

    // Create validation hints
    const hints = {
      length: { text: "At least 8 characters", valid: false },
      uppercase: { text: "At least 1 uppercase letter", valid: false },
      number: { text: "At least 1 number", valid: false },
      special: { text: "At least 1 special character", valid: false },
      spaces: { text: "No spaces", valid: false },
    };

    Object.keys(hints).forEach((key) => {
      const hintDiv = document.createElement("div");
      hintDiv.className = "validation-hint invalid";
      hintDiv.innerHTML = `<span class="validation-icon">✗</span> ${hints[key].text}`;
      hintDiv.id = `${input.id}-${key}-hint`;
      validationContainer.appendChild(hintDiv);
    });

    // Insert validation container after the input group
    const parent = input.parentNode.parentNode; // Get the column div
    const inputGroup = parent.querySelector(".input-group");
    if (inputGroup && inputGroup.nextSibling) {
      parent.insertBefore(validationContainer, inputGroup.nextSibling);
    } else {
      parent.appendChild(validationContainer);
    }

    input.addEventListener("input", function () {
      const password = this.value;

      // Update validation states
      hints.length.valid = password.length >= 8;
      hints.uppercase.valid = /[A-Z]/.test(password);
      hints.number.valid = /\d/.test(password);
      hints.special.valid = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(
        password
      );
      hints.spaces.valid = !/\s/.test(password);

      // Update UI
      Object.keys(hints).forEach((key) => {
        const hintDiv = document.getElementById(`${input.id}-${key}-hint`);
        if (hintDiv) {
          const icon = hintDiv.querySelector(".validation-icon");

          if (hints[key].valid) {
            hintDiv.classList.remove("invalid");
            hintDiv.classList.add("valid");
            icon.textContent = "✓";
          } else {
            hintDiv.classList.remove("valid");
            hintDiv.classList.add("invalid");
            icon.textContent = "✗";
          }
        }
      });

      // Update overall validation
      const isValid = Object.values(hints).every((hint) => hint.valid);
      if (isValid) {
        input.classList.remove("is-invalid");
        input.classList.add("is-valid");
      } else {
        input.classList.remove("is-valid");
        input.classList.add("is-invalid");
      }

      // Trigger OTP section visibility check
      if (typeof checkPasswords === "function") {
        checkPasswords();
      }

      // Update password strength in modal if function exists
      if (typeof updatePasswordStrength === "function") {
        updatePasswordStrength(password);
      }
    });
  });

  // Confirm password validation
  const confirmPasswordInputs = document.querySelectorAll(".confirm-password");
  confirmPasswordInputs.forEach((input) => {
    const targetId = input.getAttribute("data-match");
    const targetInput = document.getElementById(targetId);

    if (!targetInput) return;

    input.addEventListener("input", function () {
      if (this.value === targetInput.value && this.value !== "") {
        this.classList.remove("is-invalid");
        this.classList.add("is-valid");
      } else {
        this.classList.remove("is-valid");
        this.classList.add("is-invalid");
      }

      // Trigger OTP section visibility check
      if (typeof checkPasswords === "function") {
        checkPasswords();
      }
    });

    targetInput.addEventListener("input", function () {
      if (input.value === this.value && input.value !== "") {
        input.classList.remove("is-invalid");
        input.classList.add("is-valid");
      } else {
        input.classList.remove("is-valid");
        input.classList.add("is-invalid");
      }

      // Trigger OTP section visibility check
      if (typeof checkPasswords === "function") {
        checkPasswords();
      }
    });
  });
});
