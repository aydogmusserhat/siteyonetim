// static/js/app.js

// Sidebar aç/kapa (mobil)
(function () {
  const sidebar = document.getElementById("sidebar");
  const toggleBtn = document.getElementById("sidebarToggleBtn");
  const closeBtn = document.getElementById("sidebarCloseBtn");

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("sidebar--open");
    });
  }

  if (closeBtn && sidebar) {
    closeBtn.addEventListener("click", () => {
      sidebar.classList.remove("sidebar--open");
    });
  }

  // Flash mesajlarını bir süre sonra yumuşakça kaybet
  const flashes = document.querySelectorAll(".flash");
  if (flashes.length) {
    setTimeout(() => {
      flashes.forEach((el) => {
        el.style.opacity = "0";
        el.style.transform = "translateY(-4px)";
        el.style.transition = "opacity .3s ease, transform .3s ease";
        setTimeout(() => {
          if (el && el.parentElement) {
            el.parentElement.removeChild(el);
          }
        }, 320);
      });
    }, 3000);
  }
})();
