document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = form.querySelector('input[type="email"]').value.trim();
    const password = form.querySelector('input[type="password"]').value.trim();

    if (!email || !password) {
      alert("Please fill in both fields!");
      return;
    }

    const popup = document.getElementById("popup");
    const popupMsg = document.getElementById("popup-message");
    const popupBtn = document.getElementById("popup-btn");

    try {
      const res = await fetch("http://localhost:5000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (res.ok) {
        // ✅ Save JWT token
        localStorage.setItem("token", data.token);

        // ✅ Success popup
        popup.classList.remove("error");
        popupMsg.textContent = "Login successful! Welcome back 🔒";
        popupBtn.textContent = "Let's Go 🚀";
        popup.classList.add("show");
        popup.classList.add("success");

        popupBtn.onclick = () => {
          popup.classList.remove("show");
          setTimeout(() => {
            window.location.href = "dashboard.html";
          }, 300);
        };
      } else {
        // ❌ Wrong email or password popup
        popup.classList.add("error");
        popupMsg.textContent = data.msg || "Invalid email or password ❌";
        popupBtn.textContent = "Try Again";
        popup.classList.add("show");

        popupBtn.onclick = () => {
          popup.classList.remove("show");
          popup.classList.remove("error");
          popupBtn.textContent = "Let's Go 🚀";
        };
      }
    } catch (err) {
      console.error(err);

      // ❌ Network / server error popup
      popup.classList.add("error");
      popupMsg.textContent = "Something went wrong — try again later.";
      popupBtn.textContent = "Try Again";
      popup.classList.add("show");

      popupBtn.onclick = () => {
        popup.classList.remove("show");
        popup.classList.remove("error");
        popupBtn.textContent = "Let's Go 🚀";
      };
    }
  });
});
