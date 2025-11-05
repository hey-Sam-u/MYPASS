const form = document.getElementById("changeNameForm");
const popup = document.getElementById("popup");
const popupMsg = document.getElementById("popupMessage");
const closePopup = document.getElementById("closePopup");
const goBackBtn = document.getElementById("goBack");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const newName = document.getElementById("newName").value.trim();

  if (!newName) return showPopup("Please enter a new name.");

  try {
    const token = localStorage.getItem("token");
    const res = await fetch("http://localhost:5000/api/user/change-name", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ newName }),
    });

    const data = await res.json();
    if (res.ok) {
      showPopup("✅ " + data.msg);
    } else {
      showPopup("⚠️ " + data.msg);
    }
  } catch (err) {
    showPopup("Server error. Try again later.");
  }
});

function showPopup(msg) {
  popupMsg.textContent = msg;
  popup.classList.remove("hidden");
}

closePopup.addEventListener("click", () => {
  // ✅ Close + refresh the page
  popup.classList.add("hidden");
  location.reload();
});

goBackBtn.addEventListener("click", () => {
  // ✅ Go back to dashboard
  window.location.href = "dashboard.html";
});
