// change-email.js
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("change-email-form");
  const popup = document.getElementById("ce-popup");
  const pTitle = document.getElementById("ce-popup-title");
  const pMsg = document.getElementById("ce-popup-msg");
  const pOk = document.getElementById("ce-popup-ok");

  function showPopup(title, msg) {
    pTitle.innerText = title;
    pMsg.innerText = msg;
    popup.classList.remove("hidden");
  }

  pOk.addEventListener("click", () => {
    popup.classList.add("hidden");
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const current = document.getElementById("current-pass").value.trim();
    const newEmail = document.getElementById("new-email").value.trim();
    const confirmEmail = document.getElementById("confirm-email").value.trim();

    if (!current || !newEmail || !confirmEmail) {
      return showPopup("Error ⚠️", "All fields are required.");
    }
    if (newEmail !== confirmEmail) {
      return showPopup("Error ⚠️", "Emails do not match.");
    }
    // basic email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(newEmail)) {
      return showPopup("Error ⚠️", "Enter a valid email address.");
    }

    try {
      const token = localStorage.getItem("token") || "";

      const res = await fetch("/api/change-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ current, newEmail }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        showPopup("Success ✅", data.msg || "Email updated successfully.");
        form.reset();
      } else {
        // show server-provided message if any
        showPopup("Error ⚠️", data.msg || data.message || "Update failed.");
      }
    } catch (err) {
      console.error("Change-email error:", err);
      showPopup("Error ⚠️", "Network or server error. Try again.");
    }
  });
});
