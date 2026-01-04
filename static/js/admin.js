// static/js/admin.js

// Basit bir küçük animasyon: istatistik kartlarını hafifçe içeri kaydır
(function () {
  const cards = document.querySelectorAll(".stat-card");
  if (!cards.length) return;

  cards.forEach((card, index) => {
    card.style.opacity = "0";
    card.style.transform = "translateY(10px)";
    setTimeout(() => {
      card.style.transition = "opacity .25s ease, transform .25s ease";
      card.style.opacity = "1";
      card.style.transform = "translateY(0)";
    }, 80 * index);
  });
})();
