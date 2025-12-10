// Notifications system for CineWave
class NotificationSystem {
  constructor() {
    this.notifications = [];
    this.unreadCount = 0;
    this.websocket = null;
    this.initialized = false;
  }

  init() {
    if (this.initialized) return;

    this.loadNotifications();
    this.setupWebSocket();
    this.setupPolling();
    this.initialized = true;
  }

  loadNotifications() {
    if (!window.userIsAuthenticated) return;

    fetch("/notifications")
      .then((response) => response.json())
      .then((data) => {
        this.notifications = data.notifications || [];
        this.unreadCount = data.unread_count || 0;
        this.updateUI();
      })
      .catch(console.error);
  }

  setupWebSocket() {
    if (!window.userIsAuthenticated) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/notifications`;

      this.websocket = new WebSocket(wsUrl);

      this.websocket.onopen = () => {
        console.log("Notifications WebSocket connected");
      };

      this.websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        this.handleWebSocketMessage(data);
      };

      this.websocket.onclose = () => {
        console.log("Notifications WebSocket disconnected");
        // Attempt to reconnect after 5 seconds
        setTimeout(() => this.setupWebSocket(), 5000);
      };

      this.websocket.onerror = (error) => {
        console.error("WebSocket error:", error);
      };
    } catch (error) {
      console.error("Failed to setup WebSocket:", error);
    }
  }

  setupPolling() {
    // Fallback polling if WebSocket fails
    setInterval(() => {
      if (!this.websocket || this.websocket.readyState !== WebSocket.OPEN) {
        this.loadNotifications();
      }
    }, 30000); // Poll every 30 seconds
  }

  handleWebSocketMessage(data) {
    switch (data.type) {
      case "new_notification":
        this.addNotification(data.notification);
        break;
      case "notification_read":
        this.markAsRead(data.notification_id);
        break;
      case "all_notifications_read":
        this.markAllAsRead();
        break;
      case "notification_count":
        this.updateCount(data.count);
        break;
    }
  }

  addNotification(notification) {
    this.notifications.unshift(notification);
    this.unreadCount++;
    this.updateUI();
    this.showDesktopNotification(notification);
  }

  markAsRead(notificationId) {
    const notification = this.notifications.find(
      (n) => n.id === notificationId
    );
    if (notification && !notification.read) {
      notification.read = true;
      this.unreadCount = Math.max(0, this.unreadCount - 1);
      this.updateUI();
    }
  }

  markAllAsRead() {
    this.notifications.forEach((notification) => {
      notification.read = true;
    });
    this.unreadCount = 0;
    this.updateUI();
  }

  updateCount(count) {
    this.unreadCount = count;
    this.updateUI();
  }

  updateUI() {
    // Update notification count badge
    const countBadge = document.getElementById("notificationCount");
    if (countBadge) {
      if (this.unreadCount > 0) {
        countBadge.textContent =
          this.unreadCount > 99 ? "99+" : this.unreadCount;
        countBadge.style.display = "block";
      } else {
        countBadge.style.display = "none";
      }
    }

    // Update notification list
    const notificationList = document.getElementById("notificationList");
    if (notificationList) {
      if (this.notifications.length === 0) {
        notificationList.innerHTML = `
                    <li class="px-3 py-2 text-center text-secondary">
                        <i class="fas fa-bell-slash fa-lg mb-2"></i>
                        <p class="mb-0 small">No notifications</p>
                    </li>
                `;
      } else {
        notificationList.innerHTML = this.notifications
          .slice(0, 5)
          .map((notification) => this.createNotificationItem(notification))
          .join("");
      }
    }
  }

  createNotificationItem(notification) {
    const timeAgo = this.formatTimeAgo(new Date(notification.created_at));
    const icon = this.getNotificationIcon(notification.type);
    const readClass = notification.read ? "" : "fw-bold";

    return `
            <li class="dropdown-item ${readClass}" style="white-space: normal;" 
                onclick="window.notificationSystem.markNotificationRead(${
                  notification.id
                })">
                <div class="d-flex align-items-start">
                    <div class="me-2" style="color: var(--primary-blue);">
                        <i class="${icon}"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="small">${notification.message}</div>
                        <div class="text-secondary" style="font-size: 0.75rem;">${timeAgo}</div>
                    </div>
                    ${
                      !notification.read
                        ? '<span class="badge bg-primary rounded-pill" style="font-size: 0.5rem;">NEW</span>'
                        : ""
                    }
                </div>
            </li>
        `;
  }

  getNotificationIcon(type) {
    const icons = {
      watchlist: "fas fa-bookmark",
      recommendation: "fas fa-star",
      system: "fas fa-cog",
      movie: "fas fa-film",
      profile: "fas fa-user",
      warning: "fas fa-exclamation-triangle",
      success: "fas fa-check-circle",
      info: "fas fa-info-circle",
    };
    return icons[type] || "fas fa-bell";
  }

  formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);

    let interval = Math.floor(seconds / 31536000);
    if (interval >= 1)
      return interval + " year" + (interval > 1 ? "s" : "") + " ago";

    interval = Math.floor(seconds / 2592000);
    if (interval >= 1)
      return interval + " month" + (interval > 1 ? "s" : "") + " ago";

    interval = Math.floor(seconds / 86400);
    if (interval >= 1)
      return interval + " day" + (interval > 1 ? "s" : "") + " ago";

    interval = Math.floor(seconds / 3600);
    if (interval >= 1)
      return interval + " hour" + (interval > 1 ? "s" : "") + " ago";

    interval = Math.floor(seconds / 60);
    if (interval >= 1)
      return interval + " minute" + (interval > 1 ? "s" : "") + " ago";

    return "Just now";
  }

  showDesktopNotification(notification) {
    // Check if browser supports notifications
    if (!("Notification" in window)) return;

    // Check if permission is granted
    if (Notification.permission === "granted") {
      this.createDesktopNotification(notification);
    } else if (Notification.permission !== "denied") {
      // Request permission
      Notification.requestPermission().then((permission) => {
        if (permission === "granted") {
          this.createDesktopNotification(notification);
        }
      });
    }
  }

  createDesktopNotification(notification) {
    const icon = this.getNotificationIcon(notification.type);

    const options = {
      body: notification.message,
      icon: "/static/favicon.ico",
      badge: "/static/favicon.ico",
      tag: "cinewave-notification",
      requireInteraction: false,
      silent: false,
    };

    const notif = new Notification("CineWave", options);

    notif.onclick = function () {
      window.focus();
      this.close();

      // Navigate based on notification type
      if (notification.url) {
        window.location.href = notification.url;
      }
    };

    // Auto-close after 5 seconds
    setTimeout(() => notif.close(), 5000);
  }

  markNotificationRead(notificationId) {
    fetch(`/notifications/${notificationId}/read`, {
      method: "POST",
      headers: {
        "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')
          .content,
      },
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          this.markAsRead(notificationId);
        }
      })
      .catch(console.error);
  }
}

// Initialize notification system
window.notificationSystem = new NotificationSystem();

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
  if (window.userIsAuthenticated) {
    window.notificationSystem.init();
  }
});
