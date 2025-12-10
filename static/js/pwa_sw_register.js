// Register Service Worker
if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker
      .register("/service-worker.js")
      .then(function (registration) {
        console.log(
          "ServiceWorker registration successful with scope: ",
          registration.scope
        );

        // Check for updates
        registration.addEventListener("updatefound", () => {
          const newWorker = registration.installing;
          newWorker.addEventListener("statechange", () => {
            if (
              newWorker.state === "installed" &&
              navigator.serviceWorker.controller
            ) {
              // New update available
              showUpdateNotification();
            }
          });
        });
      })
      .catch(function (err) {
        console.log("ServiceWorker registration failed: ", err);
      });
  });
}

// Handle install prompt
let deferredPrompt;
window.addEventListener("beforeinstallprompt", (e) => {
  // Prevent Chrome 67 and earlier from automatically showing the prompt
  e.preventDefault();
  // Stash the event so it can be triggered later
  deferredPrompt = e;
  // Show install button
  showInstallButton();
});

function showInstallButton() {
  const installButton = document.getElementById("installButton");
  if (installButton) {
    installButton.style.display = "block";
    installButton.addEventListener("click", async () => {
      // Hide the button
      installButton.style.display = "none";
      // Show the install prompt
      deferredPrompt.prompt();
      // Wait for the user to respond to the prompt
      const { outcome } = await deferredPrompt.userChoice;
      console.log(`User response to the install prompt: ${outcome}`);
      // We've used the prompt, and can't use it again, discard it
      deferredPrompt = null;
    });
  }
}

function showUpdateNotification() {
  // Create update notification
  const notification = document.createElement("div");
  notification.className = "alert alert-info alert-dismissible fade show";
  notification.innerHTML = `
        <strong>Update Available!</strong>
        <p>A new version of CineWave is available. Refresh to update.</p>
        <button type="button" class="btn btn-sm btn-primary" onclick="location.reload()">
            Refresh Now
        </button>
    `;

  document.body.prepend(notification);
}

// Create service-worker.js content
const serviceWorkerContent = `
self.addEventListener('install', event => {
    console.log('Service Worker installing.');
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    console.log('Service Worker activating.');
    return self.clients.claim();
});

self.addEventListener('fetch', event => {
    // Add caching strategies here
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                if (response) {
                    return response;
                }
                return fetch(event.request);
            })
    );
});
`;

// Note: In production, create a separate service-worker.js file with actual caching strategies
