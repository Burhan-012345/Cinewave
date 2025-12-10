document.addEventListener("DOMContentLoaded", function () {
  const trailerCards = document.querySelectorAll(".trailer-card");

  trailerCards.forEach((card) => {
    const video = card.querySelector("video");
    if (!video) return;

    card.addEventListener("mouseenter", function () {
      video.play().catch((e) => console.log("Autoplay prevented:", e));
    });

    card.addEventListener("mouseleave", function () {
      video.pause();
      video.currentTime = 0;
    });
  });

  // YouTube trailer autoplay
  const youtubeIframes = document.querySelectorAll(".youtube-trailer");

  youtubeIframes.forEach((iframe) => {
    const container = iframe.parentElement;
    let player;

    container.addEventListener("mouseenter", function () {
      if (player) {
        player.playVideo();
      }
    });

    container.addEventListener("mouseleave", function () {
      if (player) {
        player.pauseVideo();
      }
    });

    // Load YouTube API if not already loaded
    if (typeof YT === "undefined") {
      const tag = document.createElement("script");
      tag.src = "https://www.youtube.com/iframe_api";
      const firstScriptTag = document.getElementsByTagName("script")[0];
      firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
    }

    // Wait for YouTube API
    window.onYouTubeIframeAPIReady = function () {
      player = new YT.Player(iframe, {
        events: {
          onReady: onPlayerReady,
        },
      });
    };

    function onPlayerReady(event) {
      // Player is ready
    }
  });
});
