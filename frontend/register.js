document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form");
  const btn = document.querySelector(".btn");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const name = form.querySelector('input[type="text"]').value.trim();
    const email = form.querySelector('input[type="email"]').value.trim();
    const password = form.querySelector('input[type="password"]').value.trim();

    // Basic validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const localPart = email.split("@")[0].toLowerCase();

    if (!emailRegex.test(email)) return showToast("Invalid email format");
    if (password.length < 10)
      return showToast("Password must be at least 10 characters");
    if (password.toLowerCase().includes(localPart))
      return showToast("Password shouldn't contain your email name");

    // Disable button & show loading
    btn.disabled = true;
    btn.innerText = "Registering...";

    try {
      const res = await fetch("api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });

      const data = await res.json();

      if (res.status === 201) {
        showToast("✅ Account created! Redirecting...", "success");
        setTimeout(() => {
          window.location.href = "index.html";
        }, 2000);
      } else {
        showToast("❌ " + data.msg);
      }
    } catch (err) {
      showToast("Server not reachable, try again");
    }

    // Enable again
    btn.disabled = false;
    btn.innerText = "Register";
  });
});

// Simple toast popup
function showToast(msg, type = "error") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  document.body.appendChild(toast);

  setTimeout(() => toast.classList.add("show"), 100);
  setTimeout(() => toast.classList.remove("show"), 3000);
  setTimeout(() => toast.remove(), 3500);
}
