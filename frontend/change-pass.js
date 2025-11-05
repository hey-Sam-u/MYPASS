const form = document.getElementById("change-pass-form");
const popup = document.getElementById("popup");
const popupTitle = document.getElementById("popup-title");
const popupMsg = document.getElementById("popup-message");
const popupBtn = document.getElementById("popup-btn");

// 🧠 Token from login (must be saved in localStorage at login time)
const token = localStorage.getItem("token");

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const current = document.getElementById("current-pass").value.trim();
  const newPass = document.getElementById("new-pass").value.trim();
  const confirm = document.getElementById("confirm-pass").value.trim();

  if (newPass !== confirm) {
    return showPopup("Error ⚠️", "New passwords do not match.");
  }

  if (newPass.length < 10) {
    return showPopup(
      "Error ⚠️",
      "Password must be at least 10 characters long."
    );
  }

  // ✅ Check token
  if (!token) {
    return showPopup("Error ⚠️", "You are not logged in. Please log in first.");
  }

  try {
    const res = await fetch("http://127.0.0.1:5000/api/change-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token, // 👈 include JWT
      },
      body: JSON.stringify({ current, newPass }),
    });

    const data = await res.json();

    if (res.ok) {
      showPopup("Success ✅", "Your password has been updated successfully.");
      form.reset();
    } else {
      showPopup("Error ⚠️", data.msg || "Incorrect current password.");
    }
  } catch (err) {
    console.error(err);
    showPopup("Error ⚠️", "Something went wrong, try again later.");
  }
});

popupBtn.addEventListener("click", () => {
  popup.style.display = "none";
});

function showPopup(title, message) {
  popupTitle.innerText = title;
  popupMsg.innerText = message;
  popup.style.display = "flex";
}
