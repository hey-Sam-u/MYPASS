// Animation on scroll
const cards = document.querySelectorAll(".adv-card");

window.addEventListener("scroll", () => {
  const triggerBottom = window.innerHeight * 0.85;
  cards.forEach((card) => {
    const cardTop = card.getBoundingClientRect().top;
    if (cardTop < triggerBottom) {
      card.classList.add("visible");
    }
  });
});

// Back button
document.getElementById("backBtn").addEventListener("click", () => {
  window.location.href = "dashboard.html";
});
